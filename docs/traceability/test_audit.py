"""Independent mutation cases for the offline reconciliation interface; no transport."""
import copy
import json
import unittest
import audit


class CoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = audit.load_sources()
        cls.mapping = json.loads((audit.HERE / 'component-contracts.json').read_text())
        cls.mapping['acceptance_routes'] = json.loads((audit.HERE / 'acceptance-routing-review.json').read_text())['routes']

    def rejected(self, mutation, pattern):
        data, mapping = copy.deepcopy(self.source), copy.deepcopy(self.mapping)
        mutation(data, mapping)
        with self.assertRaisesRegex(ValueError, pattern):
            audit.reconcile(data, mapping)

    def test_complete_source_preserves_annotation_and_execution_boundaries(self):
        report = audit.reconcile(self.source, self.mapping)
        self.assertEqual(report['original_annotations'], {'NOT_RUN': 564, 'OPEN_SOURCE_BLOCKER': 12})
        self.assertEqual(report['runtime_execution']['NOT_RUN'], 576)
        self.assertFalse(report['runtime_execution']['qualification_claimed'])
        self.assertEqual(len(report['component_reviews']), 147)
        self.assertEqual(len(report['acceptance_routing_review']), 88)
        self.assertEqual(report['remote_import']['reported_managed_issues'], 210)
        self.assertFalse(report['remote_import']['live_verified_by_this_tool'])

    def test_missing_workflow_package_rejected(self):
        self.rejected(lambda d,m: d['graph']['tasks'].remove(next(t for t in d['graph']['tasks'] if t['key']=='WF-I01-TEST')), 'counts changed')

    def test_duplicate_acceptance_and_orphan_rejected(self):
        self.rejected(lambda d,m: d['trace'][1].update(source_test_id=d['trace'][0]['source_test_id']), 'duplicate')
        self.rejected(lambda d,m: d['trace'][0].update(source_test_id='orphan'), 'orphan')

    def test_acceptance_misrouting_rejected(self):
        self.rejected(lambda d,m: d['trace'][0].update(verification_issue='WF-I02-VERIFY'), 'misroute')
        self.rejected(lambda d,m: d['trace'][-1].update(workflow_id='I01'), 'routing changed')

    def test_original_blocker_and_execution_promotion_rejected(self):
        self.rejected(lambda d,m: d['original'][-1].update(status='NOT_RUN'), 'annotations changed')
        self.rejected(lambda d,m: d['trace'][0].update(initial_status='PASS'), 'falsely promoted')

    def test_component_orphans_and_confirmation_invention_rejected(self):
        self.rejected(lambda d,m: m['components'].pop(), 'component coverage')
        self.rejected(lambda d,m: m['components'][0].update(association_status='CONFIRMED'), 'promoted')
        self.rejected(lambda d,m: m['components'][0].update(declared_workflows=['FAKE']), 'association drift')

    def test_human_gate_cannot_block_test_writing(self):
        def mutate(d,m):
            for rows in (d['graph']['tasks'],d['issues']['issues']):
                next(t for t in rows if t['key']=='WF-I01-TEST')['depends_on'].append('G01')
        self.rejected(mutate, 'human gate blocks')

    def test_epic_cannot_be_engineering_prerequisite(self):
        def mutate(d,m):
            for rows in (d['graph']['tasks'],d['issues']['issues']):
                next(t for t in rows if t['key']=='F01')['depends_on'].append('EP-PROGRAM')
        self.rejected(mutate, 'epic prerequisite')

    def test_build_cycle_rejected(self):
        def mutate(d,m):
            for rows in (d['graph']['tasks'],d['issues']['issues']):
                next(t for t in rows if t['key']=='F01')['depends_on'].append('F02')
                next(t for t in rows if t['key']=='F02')['depends_on']=['F01']
        self.rejected(mutate, 'cycle')

    def test_runtime_feedback_does_not_become_build_dependency(self):
        data = copy.deepcopy(self.source)
        data['catalog']['connections'][:2] = [
            {'from':'I01','to':'I02','type':'handoff'},
            {'from':'I02','to':'I01','type':'handoff'}]
        self.assertEqual(audit.reconcile(data,self.mapping)['local_source_coverage'],'COMPLETE')
        self.assertEqual(data['graph'],self.source['graph'])

    def test_unknown_runtime_endpoint_rejected(self):
        self.rejected(lambda d,m: d['catalog']['connections'][0].update(to='UNKNOWN'), 'orphan runtime')

    def test_source_bytes_allow_only_reversible_checkout_endings(self):
        original=b'one\ntwo\n'
        self.assertEqual(audit.source_bytes(original.replace(b'\n',b'\r\n')),original)
        for raw in (b'one\rtwo\r',b'one\r\ntwo\n'):
            with self.assertRaises(ValueError):audit.source_bytes(raw)


if __name__ == '__main__':
    unittest.main(verbosity=2)
