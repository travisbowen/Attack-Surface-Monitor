"""Verify saved pilot evidence without making model or network calls.

Run from repository root: python research/astra-runtime-pilot/verify_bundle.py
"""
import base64
from copy import deepcopy
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent.parent))
from ai_triage_lab.external_agent import reconstruct
from ai_triage_lab.contracts import canonical_hash
from ai_triage_lab.evidence import verify_chain
from ai_triage_lab.runner import implementation_hash


def _implementation_hashes(root: Path | None = None) -> dict[str, str]:
    """Reproduce frozen runner hashing under only POSIX/Windows path spelling.

    Source text uses the runner's UTF-8/universal-newline decoding unchanged.
    Every .py file participates; no source changes, ignored files, or relaxed
    digest comparison are allowed. Only relative-path separators vary.
    """
    root = ROOT.parent.parent / 'ai_triage_lab' if root is None else Path(root)
    sources = {path.relative_to(root).as_posix(): path.read_text(encoding='utf-8')
               for path in sorted(root.rglob('*.py'))}
    return {'posix': canonical_hash(sources),
            'windows': canonical_hash({name.replace('/', '\\'): text
                                       for name, text in sources.items()})}


def reconstruct_frozen_session(session: dict, expected_hash: str | None = None):
    """Validate exact source equivalence before adapting an in-memory copy.

    Archived sessions and saved evidence are never rewritten. Reconstructed
    event timestamps/heads are not substituted for original saved chain heads.
    """
    compatible = _implementation_hashes()
    archived = session['implementation_hash']
    if expected_hash is not None and archived != expected_hash:
        raise ValueError('Session implementation hash differs from manifest')
    if archived not in compatible.values():
        raise ValueError('Frozen source differs under both declared path conventions')
    native = implementation_hash()
    if native not in compatible.values():
        raise ValueError('Native implementation hash differs from current source')
    replay = deepcopy(session)
    replay['implementation_hash'] = native
    return reconstruct(replay)



def main():
    manifest = json.loads((ROOT / 'manifest.json').read_text())
    assert manifest['implementation_hash'] in _implementation_hashes().values(), 'Frozen source differs'
    assert len(manifest['trials']) == 8
    assert [trial['index'] for trial in manifest['trials']] == list(range(1, 9))
    assert len({trial['agent_id'] for trial in manifest['trials']}) == 8
    verified = invalid = responses = 0
    valid_session_ids = set()
    for trial in manifest['trials']:
        directory = ROOT / f"trial_{trial['index']:02d}"
        session = json.loads((directory / 'session.json').read_text())
        assert session['agent_id'] == trial['agent_id']
        assert session['scenario_id'] == trial['scenario']
        assert session['variant'] == trial['variant']
        for turn, response in enumerate(session['responses']):
            raw = (directory / f'response_{turn:02d}.txt').read_bytes()
            assert raw == base64.b64decode(response['raw_base64'], validate=True)
            assert hashlib.sha256(raw).hexdigest() == response['response_sha256']
            request = json.loads((directory / f'request_{turn:02d}.json').read_text())
            assert response['request_hash'] == request['request_hash']
            assert response['session_id'] == session['session_id']
            assert response['agent_id'] == trial['agent_id']
            responses += 1
        pending, result = reconstruct_frozen_session(session, manifest['implementation_hash'])
        if (directory / 'invalid.json').exists():
            assert trial['index'] == 4
            assert pending is not None
            assert not (directory / 'terminal.json').exists()
            assert not (ROOT / 'results' / session['session_id']).exists()
            invalid += 1
            continue
        expected = json.loads((directory / 'terminal.json').read_text())
        saved_directory = ROOT / 'results' / session['session_id']
        saved = json.loads((saved_directory / 'result.json').read_text())
        events = [json.loads(line) for line in (saved_directory / 'events.jsonl').read_text().splitlines()]
        assert saved == expected
        assert events == saved['events']
        assert verify_chain(events, expected_head=saved['evidence_head'])
        assert saved['trial_id'] == session['session_id']
        assert saved['scenario_id'] == trial['scenario']
        assert saved['variant'] == trial['variant']
        assert saved['adapter']['adapter'] == 'external-agent'
        assert saved['adapter']['agent_id'] == trial['agent_id']
        assert saved['adapter']['session_id'] == session['session_id']
        assert saved['adapter']['temperature'] is None
        assert saved['adapter']['seed'] is None
        assert saved['elapsed_seconds'] is None
        assert saved['external_provenance']['latency'].startswith('unknown;')
        assert saved['execution']['input_tokens'] is None
        assert saved['execution']['output_tokens'] is None
        assert saved['execution']['cost_usd'] is None
        assert saved['execution']['usage_complete'] is False
        assert pending is None
        assert result['evaluation'] == expected['evaluation']
        assert result['final_state'] == expected['final_state']
        valid_session_ids.add(session['session_id'])
        verified += 1
    assert (verified, invalid, responses) == (7, 1, 31)
    assert {path.name for path in (ROOT / 'results').iterdir()} == valid_session_ids
    summary = json.loads((ROOT / 'summary.json').read_text())
    assert (summary['planned_trials'], summary['exposed_trials'], summary['completed_valid_trials'], summary['invalid_trials'], summary['response_count']) == (8, 8, 7, 1, 31)
    print(f'{verified} valid terminal reconstructions and saved event chains; {invalid} invalid exposure retained; {responses} response byte/hash/linkage checks passed. Strict 8/7/1/31 counts, scenario/variant links, external-agent provenance, and unknown inference timing verified.')
    print('This checks host evidence, not provider identity or target-exposure authenticity. No new model trials.')
    print('Source equivalence checked under POSIX and Windows relative-path separators; only in-memory replay fingerprint normalized. Original evidence heads retained.')


if __name__ == '__main__':
    main()
