import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { I18nextProvider } from 'react-i18next';
import i18n from '@/test/i18nForTests';
import { LoginGate } from './LoginGate';
import { clearAuthSession } from '@/lib/authSession';

const prepareCaptcha = vi.fn();
const login = vi.fn();
const verifyOtp = vi.fn();
const restoreSession = vi.fn();

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    restoreSession: (...args: unknown[]) => restoreSession(...args),
  };
});

vi.mock('@/services/authService', () => ({
  prepareCaptcha: (...args: unknown[]) => prepareCaptcha(...args),
  login: (...args: unknown[]) => login(...args),
  verifyOtp: (...args: unknown[]) => verifyOtp(...args),
  logout: vi.fn(),
  fetchMe: vi.fn(),
  fetchAudit: vi.fn(),
  fetchUsers: vi.fn(),
}));

describe('LoginGate', () => {
  beforeEach(() => {
    clearAuthSession();
    prepareCaptcha.mockReset();
    login.mockReset();
    verifyOtp.mockReset();
    restoreSession.mockReset();
    restoreSession.mockResolvedValue(false);
    prepareCaptcha.mockResolvedValue({
      challenge: {
        parameters: {
          algorithm: 'SHA-256',
          cost: 1,
          keyLength: 32,
          keyPrefix: '00',
          nonce: 'ab',
          salt: 'cd',
        },
        signature: 'sig',
      },
      solution: { counter: 1, derivedKey: '00deadbeef' },
    });
  });

  it('renders the credentials step first', async () => {
    render(
      <I18nextProvider i18n={i18n}>
        <LoginGate><div>secure</div></LoginGate>
      </I18nextProvider>,
    );
    await waitFor(() => {
      expect(screen.getByLabelText('Username')).toBeInTheDocument();
    });
    expect(screen.getByLabelText('Password')).toBeInTheDocument();
    expect(screen.queryByText('secure')).not.toBeInTheDocument();
    expect(restoreSession).toHaveBeenCalled();
  });

  it('advances to OTP after a successful credentials + captcha step', async () => {
    const user = userEvent.setup();
    login.mockResolvedValue({
      challenge_id: 'chal-1',
      otp_required: true,
      expires_in: 300,
    });

    render(
      <I18nextProvider i18n={i18n}>
        <LoginGate><div>secure</div></LoginGate>
      </I18nextProvider>,
    );

    await screen.findByLabelText('Username');
    await user.type(screen.getByLabelText('Username'), 'root');
    await user.type(screen.getByLabelText('Password'), 'bootstrap-password-ok');
    await user.click(screen.getByRole('button', { name: 'Continue' }));

    await waitFor(() => {
      expect(prepareCaptcha).toHaveBeenCalled();
      expect(login).toHaveBeenCalledWith(
        'root',
        'bootstrap-password-ok',
        expect.objectContaining({ solution: expect.any(Object) }),
      );
    });

    expect(await screen.findByLabelText('One-time code')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Verify and sign in' })).toBeInTheDocument();
  });

  it('shows the app after a successful OTP verification', async () => {
    const user = userEvent.setup();
    login.mockResolvedValue({
      challenge_id: 'chal-2',
      otp_required: true,
      expires_in: 300,
    });
    verifyOtp.mockImplementation(async () => {
      const { applyTokenResponse } = await import('@/lib/authSession');
      applyTokenResponse({
        access_token: 'tok',
        token_type: 'Bearer',
        expires_in: 900,
        role: 'admin',
        username: 'root',
        must_change_password: false,
      });
      return {
        access_token: 'tok',
        token_type: 'Bearer',
        expires_in: 900,
        role: 'admin',
        username: 'root',
        must_change_password: false,
      };
    });

    render(
      <I18nextProvider i18n={i18n}>
        <LoginGate><div>secure</div></LoginGate>
      </I18nextProvider>,
    );

    await screen.findByLabelText('Username');
    await user.type(screen.getByLabelText('Username'), 'root');
    await user.type(screen.getByLabelText('Password'), 'secret-password');
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    await screen.findByLabelText('One-time code');
    await user.type(screen.getByLabelText('One-time code'), '123456');
    await user.click(screen.getByRole('button', { name: 'Verify and sign in' }));

    await waitFor(() => {
      expect(verifyOtp).toHaveBeenCalledWith('chal-2', '123456');
      expect(screen.getByText('secure')).toBeInTheDocument();
    });
  });

  it('signs in without the OTP step when the broker says the code is off', async () => {
    const user = userEvent.setup();
    login.mockImplementation(async () => {
      const { applyTokenResponse } = await import('@/lib/authSession');
      const tokens = {
        access_token: 'tok',
        token_type: 'Bearer',
        expires_in: 1800,
        role: 'analyst' as const,
        username: 'root',
        must_change_password: false,
        otp_required: false as const,
      };
      applyTokenResponse(tokens);
      return tokens;
    });

    render(
      <I18nextProvider i18n={i18n}>
        <LoginGate><div>secure</div></LoginGate>
      </I18nextProvider>,
    );

    await screen.findByLabelText('Username');
    await user.type(screen.getByLabelText('Username'), 'root');
    await user.type(screen.getByLabelText('Password'), 'secret-password');
    await user.click(screen.getByRole('button', { name: 'Continue' }));

    await waitFor(() => {
      expect(screen.getByText('secure')).toBeInTheDocument();
    });
    expect(screen.queryByLabelText('One-time code')).not.toBeInTheDocument();
    expect(verifyOtp).not.toHaveBeenCalled();
  });

  it('skips the login form when cookie restore succeeds', async () => {
    restoreSession.mockImplementation(async () => {
      const { applyTokenResponse } = await import('@/lib/authSession');
      applyTokenResponse({
        access_token: 'restored',
        token_type: 'Bearer',
        expires_in: 900,
        role: 'analyst',
        username: 'alice',
        must_change_password: false,
      });
      return true;
    });

    render(
      <I18nextProvider i18n={i18n}>
        <LoginGate><div>secure</div></LoginGate>
      </I18nextProvider>,
    );

    await waitFor(() => {
      expect(screen.getByText('secure')).toBeInTheDocument();
    });
    expect(screen.queryByLabelText('Username')).not.toBeInTheDocument();
  });
});
