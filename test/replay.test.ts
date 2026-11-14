// The guided demo displays analyses derived from the SIGNED response bytes only
// (audit F4), and human corrections never alter signed output (audit F5).
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { ANALYST_NOTES } from '../shared/annotations.ts';
import { SAMPLES } from '../shared/samples.ts';
import { deriveRecordedRun, ReplayIntegrityError, type SavedRun } from '../server/triage/replay.ts';
import { interpretResponse } from '../server/triage/triage.ts';
import type { EvidenceBundle } from '../server/verifier/evidence.ts';
import { triageMarkdown, untrusted } from '../web/src/exporters.ts';
import type { TriageRun } from '../web/src/types.ts';

const load = <T>(p: string) => JSON.parse(readFileSync(p, 'utf8')) as T;
const sample = (id: string) => SAMPLES.find((s) => s.id === id)!;
const ev = (id: string) => load<EvidenceBundle>(`evidence/samples/${id}/evidence.json`);
const saved = (id: string) => load<SavedRun>(`evidence/samples/${id}/run.json`);

describe('recorded runs are derived from authenticated bytes (audit F4)', () => {
  for (const s of SAMPLES) {
    it(`${s.id}: displayed analysis is the analysis parsed from the signed response`, () => {
      const b = ev(s.id);
      const r = deriveRecordedRun(s, b, saved(s.id));
      assert.equal(r.receipt.verdict, 'VERIFIED');
      assert.deepEqual(r.outcome, interpretResponse(b.completion!.status, Buffer.from(b.completion!.response_b64!, 'base64')));
      assert.equal(r.provenance.kind, 'recorded');
      assert.equal(r.provenance.response_sha256, r.receipt.response_sha256);
    });
  }

  it('the audit PoC: an altered saved analysis (run.json) fails the build', () => {
    const run = saved('lumora-staking') as SavedRun & { outcome: { triage: { title: string; summary: string } } };
    run.outcome.triage.title = 'FORGED UNSIGNED ANALYSIS';
    run.outcome.triage.summary = 'This displayed analysis was not signed by the model enclave.';
    assert.throws(() => deriveRecordedRun(sample('lumora-staking'), ev('lumora-staking'), run), (e) => e instanceof ReplayIntegrityError && /differs from the analysis parsed from the signed response/.test(e.message));
  });

  it('a subtle edit (one recommended action) fails the build too', () => {
    const run = saved('quillmark-ssrf') as SavedRun & { outcome: { triage: { recommended_actions: { action: string }[] } } };
    run.outcome.triage.recommended_actions[0]!.action = 'Use IMDSv2.';
    assert.throws(() => deriveRecordedRun(sample('quillmark-ssrf'), ev('quillmark-ssrf'), run), ReplayIntegrityError);
  });

  it('genuine evidence of a DIFFERENT sample cannot be shown under this sample', () => {
    assert.throws(() => deriveRecordedRun(sample('lumora-staking'), ev('quillmark-ssrf'), saved('quillmark-ssrf')), /not the triage request for sample "lumora-staking"/);
  });

  it('a sample whose text was edited no longer matches its recording', () => {
    const edited = { ...sample('tesserine-timing'), body: sample('tesserine-timing').body.replace('2', '3') };
    assert.throws(() => deriveRecordedRun(edited, ev('tesserine-timing'), saved('tesserine-timing')), ReplayIntegrityError);
  });

  it('a tampered marker or hygiene result in run.json fails the build', () => {
    const m = saved('lumora-staking');
    m.marker = '000000000000';
    assert.throws(() => deriveRecordedRun(sample('lumora-staking'), ev('lumora-staking'), m), /marker/);
    const h = saved('tesserine-timing');
    h.hygiene = [];
    assert.throws(() => deriveRecordedRun(sample('tesserine-timing'), ev('tesserine-timing'), h), /hygiene/);
  });

  it('response bytes that do not hash to the signed hash fail the build', () => {
    const b = ev('lumora-staking');
    b.completion!.response_b64 = Buffer.from('{"id":"x"}').toString('base64');
    assert.throws(() => deriveRecordedRun(sample('lumora-staking'), b, saved('lumora-staking')), /response bytes/);
  });
});

describe('analyst corrections (audit F5)', () => {
  it('the Quillmark IMDS correction is attached, bound to the signed response, and quotes signed text', () => {
    const r = deriveRecordedRun(sample('quillmark-ssrf'), ev('quillmark-ssrf'), saved('quillmark-ssrf'));
    assert.equal(r.analyst_notes.length, 1);
    const n = r.analyst_notes[0]!;
    assert.equal(n.response_sha256, r.receipt.response_sha256);
    assert.ok(r.outcome.triage!.recommended_actions.some((a) => a.action === n.quote), 'the corrected action is still shown verbatim');
    assert.match(n.body.join(' '), /security groups .* do not filter/i);
    // The signed evidence is untouched: the receipt still verifies over the original bytes.
    assert.equal(r.receipt.verdict, 'VERIFIED');
  });

  it('no correction is attached to other runs', () => {
    assert.equal(deriveRecordedRun(sample('lumora-staking'), ev('lumora-staking'), saved('lumora-staking')).analyst_notes.length, 0);
  });

  it('a correction quoting text the model never said fails the build', () => {
    const fake = { ...ANALYST_NOTES[0]!, id: 'fake', quote: 'Text the model never produced.' };
    ANALYST_NOTES.push(fake);
    try {
      assert.throws(() => deriveRecordedRun(sample('quillmark-ssrf'), ev('quillmark-ssrf'), saved('quillmark-ssrf')), /quotes text that is not in the signed output/);
    } finally {
      ANALYST_NOTES.pop();
    }
  });

  it('the Markdown export carries the correction, the provenance and the transmission state', () => {
    const r = deriveRecordedRun(sample('quillmark-ssrf'), ev('quillmark-ssrf'), saved('quillmark-ssrf'));
    const md = triageMarkdown(r as unknown as TriageRun, 'fictional sample');
    assert.match(md, /Analyst correction \(human commentary — not part of the signed model output\)/);
    assert.match(md, /recorded run \(historical receipt; not a fresh inference\)/);
    assert.match(md, /report transmission: sent/);
    assert.match(md, /complete serialized API request/);
    assert.doesNotMatch(md, /and ignored/);
  });
});

describe('exports treat model output as untrusted', () => {
  it('HTML and Markdown images/links in model text are neutralised', () => {
    assert.equal(untrusted('<img src=x onerror=alert(1)>'), '&lt;img src=x onerror=alert(1)&gt;');
    assert.equal(untrusted('![x](https://evil.example/p.png)'), '!\\[x]\\(https://evil.example/p.png)');
    assert.equal(untrusted('[a](b)'), '[a]\\(b)');
  });
});
