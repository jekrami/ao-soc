"""Broker checks split out of test_broker.py. Import after env vars are set."""
from __future__ import annotations

from tests.harness import *  # noqa: F401,F403

def check_pilot_report() -> None:
    """pilot_report.py: the seven M16 questions, computed from a store whose answers are known."""
    import hashlib
    import tempfile

    import pilot_report
    from sqlalchemy import create_engine, insert

    assert pilot_report.percentile([1, 2, 3, 4], 0.5) == 2
    assert pilot_report.percentile([1, 2, 3, 4], 0.95) == 4
    assert pilot_report.percentile([], 0.5) is None

    now = datetime(2026, 9, 1, 12, 0, 0)
    approver = pilot_report.AUTOPILOT_APPROVER
    workdir = tempfile.mkdtemp(prefix='pilot-report-')
    path = os.path.join(workdir, 'store.db')
    engine = create_engine(f'sqlite:///{path}')
    db.metadata.create_all(engine)

    serial = {'n': 0}

    def decision(source, verdict, created, *, by='sara', status='DONE', outcome=None, decision_source='llm',
                 corrected=False, approved_after=None, dispatched_after=None):
        serial['n'] += 1
        alert = f'ALT-PR{serial["n"]:03d}'
        with engine.begin() as conn:
            conn.execute(insert(db.security_events).values(
                alert_id=alert, timestamp=created, created_at=created, updated_at=created, detection_source=source))
            decision_id = conn.execute(insert(db.tier2_decisions).values(
                alert_id=alert, decision_type=verdict, decision_source=decision_source, approval_status=status,
                approved_by=None if status == 'REJECTED' else by, created_at=created,
                approved_at=created + timedelta(seconds=approved_after) if approved_after is not None else None,
                completed_at=(created + timedelta(seconds=approved_after + dispatched_after)
                              if dispatched_after is not None else None),
            )).inserted_primary_key[0]
            if corrected:
                conn.execute(insert(db.decision_corrections).values(
                    alert_id=alert, decision_id=decision_id, corrected_by=by, original_decision=verdict,
                    corrected_decision=verdict, verdict_changed=True, plan_changed=False,
                    detection_source=source, created_at=created))
            if outcome:
                conn.execute(insert(db.decision_outcomes).values(
                    alert_id=alert, decision_id=decision_id, outcome=outcome, decision_type=verdict,
                    decision_source=decision_source, detection_source=source, reported_by='sara', created_at=created))
        return alert, decision_id

    def action(alert, decision_id, status, *, reversibility='REVERSIBLE', rollback='', connector='edr'):
        with engine.begin() as conn:
            conn.execute(insert(db.alert_soar_actions).values(
                alert_id=alert, decision_id=decision_id, action_id=f'A-{alert}', action_type='Isolate host',
                target='srv-1', reversibility=reversibility, status=status, connector=connector,
                rollback_status=rollback, rollback_by='sara' if rollback == 'DONE' else None, created_at=now))

    base = now - timedelta(days=20)
    # wazuh: 10 approved as proposed, 2 edited, 1 rejected — all judged true positive where an outcome exists.
    hour = 0
    wazuh_alerts = []
    for index in range(10):
        hour += 1
        wazuh_alerts.append(decision('wazuh', 'CONTAIN', base + timedelta(hours=hour), outcome='TRUE_POSITIVE',
                                     approved_after=600 if index == 0 else None,
                                     dispatched_after=30 if index == 0 else None))
    for _ in range(2):
        hour += 1
        decision('wazuh', 'CONTAIN', base + timedelta(hours=hour), corrected=True, outcome='TRUE_POSITIVE')
    hour += 1
    decision('wazuh', 'CONTAIN', base + timedelta(hours=hour), status='REJECTED')
    # A decision the autopilot took, which a person then rolled back.
    hour += 1
    auto_alert, auto_id = decision('wazuh', 'CONTAIN', base + timedelta(hours=hour), by=approver,
                                   approved_after=2, dispatched_after=2)
    action(auto_alert, auto_id, 'DONE', rollback='DONE')
    action(wazuh_alerts[1][0], wazuh_alerts[1][1], 'DONE', reversibility='IRREVERSIBLE')
    action(wazuh_alerts[2][0], wazuh_alerts[2][1], 'BLOCKED')

    # noisy: three confirmed, then nine false positives — a gate that opens on three would be wrong every time.
    for index in range(12):
        decision('noisy-ids', 'CONTAIN', base + timedelta(hours=hour + 1 + index),
                 outcome='TRUE_POSITIVE' if index < 3 else 'FALSE_POSITIVE', decision_source='rules')

    # old: three confirmations a hundred days ago, then one today — enough history, none of it fresh.
    for days in (100, 99, 98):
        decision('old-siem', 'CONTAIN', now - timedelta(days=days), outcome='TRUE_POSITIVE')
    decision('old-siem', 'CONTAIN', now - timedelta(hours=1), outcome='TRUE_POSITIVE')

    # Latency: two situations, received 5s and 15s before their decision, occurred 60s before that.
    with engine.begin() as conn:
        for number, (alert, _decision_id) in enumerate(wazuh_alerts[:2]):
            created = conn.execute(sqlalchemy.select(db.tier2_decisions.c.created_at)
                                   .where(db.tier2_decisions.c.alert_id == alert)).scalar_one()
            received = created - timedelta(seconds=(5, 15)[number])
            conn.execute(insert(db.situations).values(
                situation_id=f'SIT-PR{number}', alert_id=alert, first_seen=received, last_seen=received,
                detection_count=3 if number == 0 else 1, source_count=2 if number == 0 else 1,
                created_at=received, updated_at=received))
            conn.execute(insert(db.detections).values(
                detection_id=f'DET-PR{number}', situation_id=f'SIT-PR{number}', source_tool='wazuh',
                detected_at=received - timedelta(seconds=60), received_at=received, created_at=received))
        conn.execute(insert(db.situations).values(
            situation_id='SIT-MERGED', status='MERGED', detection_count=9, source_count=3,
            first_seen=now, last_seen=now, created_at=now, updated_at=now))

        good_prompt, good_response = 'situation', '{"decision":"CONTAIN"}'
        for run, (prompt, response_text, retained, hash_of) in enumerate((
            (good_prompt, good_response, True, (good_prompt, good_response)),
            (good_prompt, good_response, True, (good_prompt, good_response)),
            (good_prompt, good_response + ' tampered', True, (good_prompt, good_response)),
            (None, None, False, (good_prompt, good_response)),
        )):
            digest = hashlib.sha256(hash_of[0].encode() + b'\x00' + hash_of[1].encode()).hexdigest()
            conn.execute(insert(db.model_runs).values(
                run_id=f'RUN-PR{run}', provider='ollama', model_id='qwen2.5:7b', prompt_sha256='0' * 64,
                response_sha256='0' * 64, reasoning_hash=digest, text_retained=retained, prompt_text=prompt,
                response_text=response_text, latency_ms=1000 * (run + 1), created_at=now))
        conn.execute(insert(db.analysis_jobs).values(
            situation_id='SIT-PR0', status='FAILED', next_attempt_at=now, created_at=now, updated_at=now))

    backups = os.path.join(workdir, 'backups')
    os.makedirs(backups)
    archive = os.path.join(backups, 'AfraSOC-20260901T000000.db')
    shutil.copyfile(path, archive)
    with open(archive + '.manifest.json', 'w', encoding='utf-8') as handle:
        json.dump({'sha256': hashlib.sha256(open(archive, 'rb').read()).hexdigest(),
                   'created_at': '2026-09-01T00:00:00+00:00'}, handle)

    before = hashlib.sha256(open(path, 'rb').read()).hexdigest()
    report = pilot_report.build_report(path, min_decisions=10, min_judged=5, backup_dir=backups, now=now)
    # Read-only: the store is byte-identical afterwards, and the connection could not have written to it.
    assert hashlib.sha256(open(path, 'rb').read()).hexdigest() == before
    probe = pilot_report._connect(path)
    try:
        probe.execute('DELETE FROM tier2_decisions')
    except sqlite3.OperationalError:
        pass
    else:
        raise AssertionError('the report must open the store read-only')
    finally:
        probe.close()
    json.dumps(report)
    text = pilot_report.render_text(report)
    assert 'M16' in text and '1. Correlation' in text and '7. Backups' in text

    # 1. Correlation: a merged situation holds nothing, and is not counted.
    q1 = report['q1_correlation']
    assert q1['situations'] == 2 and q1['detections'] == 4 and q1['multi_source_situations'] == 1, q1
    assert q1['correlated_situations'] == 1 and q1['alerts_a_human_did_not_triage'] == 2, q1

    # 2. Agreement. wazuh 10 + noisy 12 + old 4 unchanged; 2 edited; 1 rejected; the autopilot's is not a human's.
    q2 = report['q2_verdict_agreement']
    assert (q2['approved_unchanged'], q2['edited'], q2['rejected'], q2['autopilot']) == (26, 2, 1, 1), q2
    assert q2['human_judged'] == 29 and q2['agreement_rate'] == round(26 / 29, 3), q2
    assert q2['reversed_after_execution'] == 1 and q2['status'] == pilot_report.ANSWERED, q2
    assert q2['by_detection_source']['wazuh']['edited'] == 2 and q2['by_detection_source']['wazuh']['rejected'] == 1

    # 3. Precision per source, and the source that should stay with a human.
    q3 = report['q3_precision_per_source']
    assert q3['by_detection_source']['wazuh']['precision'] == 1.0
    assert q3['by_detection_source']['noisy-ids']['precision'] == 0.25, q3
    assert q3['by_detection_source']['old-siem']['enough'] is False, 'four judgements are not a precision'
    assert q3['not_worth_automating'] == ['noisy-ids'], q3

    # 4. The gate: opens on the 4th of a run of three confirmations. wazuh 12 outcomes -> 9 open, all held;
    #    noisy 12 -> 9 open, none held; old-siem's history is stale, so it is closed by the window alone.
    q4 = report['q4_gate_constants']
    configured = q4['configured']
    assert (configured['opened'], configured['held'], configured['wrongly_opened']) == (18, 9, 9), configured
    assert configured['hold_rate'] == 0.5 and configured['closed_by_staleness_only'] == 1, configured
    assert configured['groups']['wazuh / CONTAIN'] == {'opened': 9, 'held': 9}, configured['groups']
    assert q4['sweep_min_precedents'][0]['min_precedents'] == 1 and q4['status'] == pilot_report.ANSWERED
    assert 'upper bound' in q4['similarity_note']

    # 5. Actions, from receipts.
    q5 = report['q5_actions']
    assert q5['total'] == 3 and q5['dispatched_and_reached'] == 2 and q5['blocked_before_leaving'] == 1, q5
    assert q5['dispatched_by_autopilot'] == 1 and q5['irreversible_dispatched'] == 1 and q5['rolled_back'] == 1, q5
    assert len(q5['flagged_for_review']) == 2, q5['flagged_for_review']

    # 6. Latency: nearest-rank percentiles of values that occurred.
    q6 = report['q6_latency']
    assert q6['detection_received_to_decision']['n'] == 2 and q6['detection_received_to_decision']['p50'] == 5
    assert q6['detection_received_to_decision']['p95'] == 15
    assert q6['detection_received_to_decision']['p95_reliable'] is False, 'two samples do not make a p95'
    assert q6['detection_occurred_to_decision']['p95'] == 75
    assert q6['decision_to_approval_human_wait']['p50'] == 600
    assert q6['approval_to_dispatch_complete_human']['p50'] == 30
    assert q6['approval_to_dispatch_complete_autopilot']['p50'] == 2
    assert q6['model_call']['n'] == 4

    # 7. A backup exists, but nothing shows one was restored: a person must say so.
    q7 = report['q7_backups']
    assert q7['backups_found'] == 1 and q7['newest'][0]['sha256_matches_manifest'] is True, q7
    assert q7['status'] == pilot_report.NEEDS_A_PERSON, q7
    open(path + '.replaced-20260901T010000', 'wb').close()
    assert pilot_report.build_report(path, min_decisions=10, min_judged=5, backup_dir=backups, now=now
                                     )['q7_backups']['status'] == pilot_report.ANSWERED

    # Whether it can be believed: tamper detection, dead letters, the fallback share.
    ctx = report['context']
    assert ctx['model_runs'] == {'total': 4, 'by_model': {'qwen2.5:7b': 4}, 'verified': 2, 'mismatch': 1,
                                 'text_not_retained': 1}, ctx['model_runs']
    assert ctx['dead_letters'] == 1 and ctx['corrections'] == 2, ctx
    assert any('no longer match' in item for item in report['warnings']), report['warnings']
    assert any('dead letters' in item for item in report['warnings']), report['warnings']

    # "Insufficient data" is an answer, and a number is not offered in its place.
    thin = pilot_report.build_report(path, min_decisions=500, min_judged=500, backup_dir=backups, now=now)
    for key in ('q1_correlation', 'q2_verdict_agreement', 'q3_precision_per_source', 'q4_gate_constants'):
        assert thin[key]['status'] == pilot_report.INSUFFICIENT and thin[key]['why'], (key, thin[key])
    assert '[INSUFFICIENT DATA]' in pilot_report.render_text(thin)

    # A window keeps only what is inside it.
    recent = pilot_report.build_report(path, since_days=2, min_decisions=1, min_judged=1, backup_dir=backups, now=now)
    assert recent['q2_verdict_agreement']['human_judged'] < q2['human_judged']

    # A pilot with decisions and no corrections has not been run.
    with engine.begin() as conn:
        conn.execute(db.decision_corrections.delete())
    assert any('has not been run' in item for item in
               pilot_report.build_report(path, backup_dir=backups, now=now)['warnings'])

    # A missing store is an error, not an empty report.
    try:
        pilot_report.build_report(os.path.join(workdir, 'absent.db'))
    except FileNotFoundError:
        pass
    else:
        raise AssertionError('a missing database must not read as an empty pilot')

    engine.dispose()
    shutil.rmtree(workdir, ignore_errors=True)


def check_backup_roundtrip() -> None:
    """E4: a backup that cannot be verified is not a backup."""
    import backup

    scratch = 'test_backup_dir'
    shutil.rmtree(scratch, ignore_errors=True)
    manifest = backup.create_backup(source='test_soc_matrix.db', out_dir=scratch)
    archive = os.path.join(scratch, manifest['archive'])

    assert manifest['integrity'] == 'ok'
    assert manifest['rows']['tier2_decisions'] >= 1, manifest['rows']
    assert manifest['app_version'] != 'unknown', 'an archive must name the build that wrote it'

    verified = backup.verify_backup(archive)
    assert verified['manifest_matches'] is True

    # A tampered archive raises rather than returning something plausible
    # (playbook §9: verify recovered bytes, and a mismatch raises).
    with open(archive, 'ab') as handle:
        handle.write(b'\x00')
    try:
        backup.verify_backup(archive)
    except RuntimeError as exc:
        assert 'does not match its manifest' in str(exc)
    else:
        raise AssertionError('a tampered archive verified clean')

    shutil.rmtree(scratch, ignore_errors=True)

