import { solveChallenge } from 'altcha-lib';
import { deriveKey } from 'altcha-lib/algorithms/web/sha';
import type { CaptchaChallenge, CaptchaPayload } from '@/types/auth';

/**
 * Solve an ALTCHA v2 challenge issued by GET /api/auth/captcha.
 * Returns the payload shape the broker expects under `captcha` on login.
 */
export async function solveCaptcha(challenge: CaptchaChallenge): Promise<CaptchaPayload> {
  const solution = await solveChallenge({
    challenge: {
      parameters: challenge.parameters,
      signature: challenge.signature,
    },
    deriveKey,
  });
  if (!solution) {
    throw new Error('Captcha challenge could not be solved');
  }
  return {
    challenge: {
      parameters: challenge.parameters,
      signature: challenge.signature,
    },
    solution: {
      counter: solution.counter,
      derivedKey: solution.derivedKey,
      ...(solution.time !== undefined ? { time: solution.time } : {}),
    },
  };
}
