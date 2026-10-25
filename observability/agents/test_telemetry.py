"""Authored F17 offline tests. No controller DB, models or external services."""
import copy
import contextlib
import io
from decimal import localcontext
from unittest.mock import patch
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import telemetry as t
from export_snapshot import write_reports

NOW='2026-10-25T12:01:00Z'

def snapshot():
    return json.loads((Path(__file__).parent/'fixtures/synthetic-snapshot.json').read_text(encoding='utf-8-sig'))

class TelemetryTests(unittest.TestCase):
    def test_counts_ages_leases_and_safe_bindings(self):
        report=t.render(snapshot(),NOW)
        self.assertEqual(report['counts']['READY'],1)
        self.assertEqual(report['counts']['RUNNING'],1)
        self.assertEqual(report['counts']['BLOCKED'],1)
        self.assertEqual(report['active_leases'],1)
        self.assertEqual(report['queue_oldest_age_seconds'],60)
        self.assertEqual(report['merge_wait_oldest_seconds'],120)
        self.assertEqual(report['evidence_oldest_age_seconds'],120)
        self.assertEqual(report['missing_evidence_count'],2)
        self.assertTrue(report['admission_signal'])
        self.assertFalse(report['dispatch_authorized'])
        self.assertEqual(report['tasks'][1]['agent_ref'],'agent:synthetic-worker')
        self.assertTrue(report['tasks'][1]['input_ref'].startswith('sha256:'))

    def test_accepted_f08_holds_remain_holds(self):
        data=snapshot()
        data['dispatch_inputs']=json.loads((t.ROOT/'docs/orchestration/capacity/dispatch-inputs.json').read_text())
        report=t.render(data,NOW)
        self.assertFalse(report['admission_signal'])
        self.assertIn('capacity_inputs_held',report['admission_hold_reasons'])

    def test_subscription_exhaustion_denies_without_inventing_dollars(self):
        data=snapshot();data['accounting']['subscription_tasks_used']=9
        report=t.render(data,NOW)
        self.assertFalse(report['admission_signal'])
        self.assertIn('subscription_budget_exhausted',report['admission_hold_reasons'])
        self.assertEqual(report['accounting']['api_spent_usd'],'0.00')
        self.assertEqual(report['billing_mode'],'ChatGPT subscription')

    def test_zero_api_budget_blocks_actual_or_reserved_spend(self):
        for key in ('api_spent_usd','api_reserved_usd'):
            data=snapshot();data['accounting'][key]='0.01'
            with self.subTest(key=key):
                report=t.render(data,NOW)
                self.assertFalse(report['admission_signal'])
                self.assertIn('api_budget_exceeded',report['admission_hold_reasons'])

    def test_unknown_accounting_stays_unknown(self):
        data=snapshot();data['accounting']['api_spent_usd']=None
        data['accounting']['subscription_task_limit']=None
        report=t.render(data,NOW);prom=t.prometheus(report)
        self.assertIsNone(report['accounting']['api_spent_usd'])
        self.assertIn('agent_api_spent_usd_known 0',prom)
        self.assertNotIn('\nagent_api_spent_usd ',prom)
        self.assertFalse(report['admission_signal'])

    def test_emergency_stop_staleness_and_orphans_deny(self):
        for case in ('stop','stale','orphan','expired'):
            data=snapshot()
            if case=='stop':data['emergency_stop']=True
            if case=='stale':data['observed_at']='2026-10-25T11:50:00Z';data['tasks']=[]
            if case=='orphan':data['tasks'][1]['state']='ORPHANED'
            if case=='expired':data['tasks'][1]['lease_until']='2026-10-25T12:00:00Z'
            with self.subTest(case=case):self.assertFalse(t.render(data,NOW)['admission_signal'])
        data=snapshot();data['tasks'][1]['state']='ORPHANED'
        report=t.render(data,NOW)
        self.assertEqual(report['counts']['ORPHANED'],1)
        self.assertEqual(report['tasks'][1]['state'],'ORPHANED')

    def test_resource_pressure_and_unknown_not_added_across_hosts(self):
        data=snapshot();data['resources']['memory_mib']['allocated']=4096
        self.assertFalse(t.render(data,NOW)['admission_signal'])
        data=snapshot();data['resources']['memory_mib']['capacity']=None
        report=t.render(data,NOW)
        self.assertIsNone(report['resource_pressure_ratio']['memory_mib'])
        self.assertFalse(report['admission_signal'])
        self.assertNotIn('windows',report)
        self.assertNotIn('wsl',report)

    def test_metric_labels_are_fixed_and_never_task_identifiers(self):
        report=t.render(snapshot(),NOW);prom=t.prometheus(report)
        for forbidden in ('synthetic-worker','F17-SYNTHETIC','sha256:','git:','artifact:','prompt','credential'):
            self.assertNotIn(forbidden,prom)
        self.assertLess(len(prom.splitlines()),100)
        self.assertIn('agent_tasks{state="READY"}',prom)
        self.assertIn('role="implementation",measure="input_tokens"',prom)

    def test_raw_dispatch_text_is_not_exported(self):
        data=snapshot();data['dispatch_inputs']['user_provider_instruction']='private-fixture-sentinel'
        data['dispatch_inputs']['credential_broker_ref']='private-broker-sentinel'
        report=t.render(data,NOW)
        self.assertNotIn('private-fixture-sentinel',t.canonical(report))
        self.assertNotIn('private-broker-sentinel',t.prometheus(report))

    def test_unknown_fields_are_rejected_without_redaction_guessing(self):
        for where in ('root','task','resource','usage','accounting'):
            data=snapshot()
            target={'root':data,'task':data['tasks'][0],'resource':data['resources']['cpu'],
                    'usage':data['model_usage']['implementation'],'accounting':data['accounting']}[where]
            target['raw_prompt']='synthetic-sensitive-payload'
            with self.subTest(where=where),self.assertRaises(ValueError):t.render(data,NOW)

    def test_invalid_identity_hash_and_label_values_rejected(self):
        for key,value in [('agent_ref','person@example.invalid'),('input_ref','sha256:'+'a'*64+'\n'),
                          ('base_ref','git:short'),('result_ref','../credentials'),('state','READY"} 9\nattack')]:
            data=snapshot();data['tasks'][0][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):t.render(data,NOW)
        data=snapshot();data['model_usage']['unknown-model']=data['model_usage']['review']
        with self.assertRaises(ValueError):t.render(data,NOW)

    def test_bool_nan_negative_and_unbounded_counts_rejected(self):
        for value in (True,-1,float('nan'),float('inf'),10**30,'10'):
            data=snapshot();data['resources']['cpu']['allocated']=value
            with self.subTest(value=value),self.assertRaises(ValueError):t.render(data,NOW)

    def test_invalid_money_is_not_coerced(self):
        for value in ('NaN','1e3','-1','1.0\n',1.0,True,'9'*100):
            data=snapshot();data['accounting']['api_spent_usd']=value
            with self.subTest(value=value),self.assertRaises(ValueError):t.render(data,NOW)

    def test_duplicate_and_oversized_tasks_rejected(self):
        data=snapshot();data['tasks'].append(copy.deepcopy(data['tasks'][0]))
        with self.assertRaises(ValueError):t.render(data,NOW)
        data=snapshot();data['tasks']=[data['tasks'][0]]*(t.MAX_TASKS+1)
        with self.assertRaises(ValueError):t.render(data,NOW)

    def test_output_is_detached_from_input_mutation(self):
        data=snapshot();report=t.render(data,NOW)
        data['accounting']['api_spent_usd']='9.00'
        data['model_usage']['implementation']['calls']=999
        self.assertEqual(report['accounting']['api_spent_usd'],'0.00')
        self.assertEqual(report['model_usage']['implementation']['calls'],2)

    def test_same_snapshot_replay_is_idempotent(self):
        data=snapshot();first=t.render(data,NOW)
        self.assertEqual(t.render(data,NOW,first['cursor']),first)
        self.assertEqual(t.prometheus(first),t.prometheus(t.render(data,NOW)))

    def test_stale_or_conflicting_replay_rejected(self):
        data=snapshot();data['sequence']=5;cursor=t.render(data,NOW)['cursor']
        data['sequence']=4
        with self.assertRaises(ValueError):t.render(data,NOW,cursor)
        data['sequence']=5;data['accounting']['subscription_tasks_used']=3
        with self.assertRaises(ValueError):t.render(data,NOW,cursor)

    def test_new_sequence_still_requires_non_decreasing_observation(self):
        data=snapshot();cursor=t.render(data,NOW)['cursor']
        data['sequence']=2;data['observed_at']='2026-10-25T11:59:00Z';data['tasks']=[]
        with self.assertRaises(ValueError):t.render(data,NOW,cursor)

    def test_invalid_calendar_future_timestamp_and_empty_evidence(self):
        for stamp in ('2026-02-30T12:00:00Z','2026-10-25T13:00:00Z','2026-10-25T12:00:00'):
            data=snapshot();data['observed_at']=stamp
            with self.subTest(stamp=stamp),self.assertRaises(ValueError):t.render(data,NOW)
        data=snapshot();data['tasks']=[]
        report=t.render(data,NOW)
        self.assertIsNone(report['evidence_oldest_age_seconds'])
        self.assertIn('agent_evidence_age_known 0',t.prometheus(report))

    def test_numeric_metric_injection_is_rejected(self):
        report=t.render(snapshot(),NOW);report['counts']['READY']='1\nunsafe_metric 1'
        with self.assertRaises(ValueError):t.prometheus(report)

    def test_file_output_and_malformed_json(self):
        with tempfile.TemporaryDirectory(prefix='f17-test-') as tmp:
            root=Path(tmp);report=t.render(snapshot(),NOW);write_reports(root,report)
            self.assertEqual(json.loads((root/'agents.json').read_text()),report)
            self.assertEqual((root/'agents.prom').read_text(),t.prometheus(report))
            self.assertEqual(sorted(p.name for p in root.iterdir()),['agents.json','agents.prom'])
            bad=root/'bad.json';bad.write_text('{"sequence":1,"sequence":2}')
            with self.assertRaises(ValueError):t.read_snapshot(bad)
            bad.write_bytes(b'x'*(t.MAX_BYTES+1))
            with self.assertRaises(ValueError):t.read_snapshot(bad)

    def test_cli_failure_does_not_echo_input_or_paths(self):
        with tempfile.TemporaryDirectory(prefix='f17-test-') as tmp:
            path=Path(tmp)/'synthetic-private-sentinel.json';path.write_text('{"secret":"synthetic-credential-sentinel"}')
            result=subprocess.run([sys.executable,'-B',str(Path(__file__).with_name('export_snapshot.py')),str(path),'--now',NOW],capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,2)
            self.assertNotIn('synthetic-credential-sentinel',result.stdout+result.stderr)
            self.assertNotIn('synthetic-private-sentinel',result.stdout+result.stderr)
            self.assertFalse(json.loads(result.stdout)['dispatch_authorized'])

    def test_required_zero_capacity_holds_but_unused_gpu_is_allowed(self):
        for resource in ('cpu','memory_mib','slots'):
            data=snapshot();data['resources'][resource]={'capacity':0,'allocated':0}
            with self.subTest(resource=resource):
                report=t.render(data,NOW)
                self.assertFalse(report['admission_signal'])
                self.assertIn('required_resource_capacity_unavailable',report['admission_hold_reasons'])
        self.assertTrue(t.render(snapshot(),NOW)['admission_signal'])

    def test_requested_tasks_fit_free_execution_slots(self):
        data=snapshot();data['resources']['slots']={'capacity':2,'allocated':1}
        data['accounting']['requested_subscription_tasks']=2
        report=t.render(data,NOW)
        self.assertFalse(report['admission_signal'])
        self.assertIn('insufficient_execution_slots',report['admission_hold_reasons'])
        data['resources']['slots']['capacity']=3
        self.assertTrue(t.render(data,NOW)['admission_signal'])

    def test_active_prerequisite_evidence_missing_and_expired_hold(self):
        for index in (0,1,2):
            for value in (None,'2026-10-24T12:00:00Z'):
                data=snapshot();data['tasks'][index]['evidence_at']=value
                with self.subTest(index=index,value=value):
                    self.assertFalse(t.render(data,NOW)['admission_signal'])
        data=snapshot();data['tasks'][0]['evidence_at']='2026-10-25T11:59:00Z'
        self.assertTrue(t.render(data,NOW)['admission_signal'])
        data['tasks'][0]['evidence_at']='2026-10-25T11:58:59Z'
        self.assertFalse(t.render(data,NOW)['admission_signal'])

    def test_historical_completed_evidence_does_not_block_new_work(self):
        data=snapshot()
        completed=next(task for task in data['tasks'] if task['state']=='ACCEPTED')
        completed['evidence_at']='2026-10-24T12:00:00Z'
        report=t.render(data,NOW)
        self.assertGreater(report['evidence_oldest_age_seconds'],t.FRESHNESS_SECONDS)
        self.assertTrue(report['admission_signal'])

    def test_attempt_binding_cannot_change_after_higher_sequence(self):
        data=snapshot();cursor=t.render(data,NOW)['cursor']
        for field,value in [('input_ref','sha256:'+'1'*64),('base_ref','git:'+'2'*40)]:
            altered=copy.deepcopy(data);altered['sequence']=2;altered['tasks'][1][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):t.render(altered,NOW,cursor)

    def test_retry_requires_new_attempt_ref_and_retains_prior_binding(self):
        data=snapshot();cursor=t.render(data,NOW)['cursor'];old=data['tasks'][0]['task_ref']
        data['sequence']=2;data['tasks'][0]['task_ref']='task:F17-SYNTHETIC-A-RETRY-2'
        data['tasks'][0]['input_ref']='sha256:'+'1'*64
        report=t.render(data,NOW,cursor)
        self.assertTrue(report['admission_signal'])
        self.assertIn(old,report['cursor']['attempt_bindings'])
        self.assertIn(data['tasks'][0]['task_ref'],report['cursor']['attempt_bindings'])

    def test_disappeared_attempt_cannot_reappear_with_new_identity(self):
        original=snapshot();cursor=t.render(original,NOW)['cursor']
        missing=copy.deepcopy(original);missing['sequence']=2;missing['tasks'].pop(0)
        cursor=t.render(missing,NOW,cursor)['cursor']
        revived=copy.deepcopy(original);revived['sequence']=3;revived['tasks'][0]['base_ref']='git:'+'2'*40
        with self.assertRaises(ValueError):t.render(revived,NOW,cursor)

    def test_attempt_history_bound_and_old_cursor_fail_closed(self):
        data=snapshot();cursor=t.render(data,NOW)['cursor']
        binding=copy.deepcopy(next(iter(cursor['attempt_bindings'].values())))
        for index in range(t.MAX_ATTEMPTS-len(cursor['attempt_bindings'])):
            cursor['attempt_bindings']['task:HISTORICAL-'+str(index)]=copy.deepcopy(binding)
        data['sequence']=2
        self.assertEqual(len(t.render(data,NOW,cursor)['cursor']['attempt_bindings']),t.MAX_ATTEMPTS)
        data['tasks'][0]['task_ref']='task:ONE-MORE-ATTEMPT'
        with self.assertRaises(ValueError):t.render(data,NOW,cursor)
        old_cursor={key:value for key,value in cursor.items() if key!='attempt_bindings'}
        with self.assertRaises(ValueError):t.render(data,NOW,old_cursor)
    def run_cli(self,path,root,previous=None):
        command=[sys.executable,'-B',str(Path(__file__).with_name('export_snapshot.py')),str(path),'--now',NOW,'--output-dir',str(root)]
        if previous is not None:command.extend(['--previous-cursor',str(previous)])
        return subprocess.run(command,capture_output=True,text=True,timeout=15)

    def test_output_success_then_invalid_or_unreadable_snapshot_is_unavailable(self):
        for failure in ('invalid','missing'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory(prefix='f17-stale-') as directory:
                root=Path(directory);source=root/'snapshot.json';source.write_text(json.dumps(snapshot()))
                self.assertEqual(self.run_cli(source,root).returncode,0)
                self.assertTrue(json.loads((root/'agents.json').read_text())['admission_signal'])
                if failure=='invalid':source.write_text('{broken')
                else:source.unlink()
                failed=self.run_cli(source,root)
                self.assertEqual(failed.returncode,2)
                report=json.loads((root/'agents.json').read_text())
                self.assertFalse(report['export_available']);self.assertFalse(report['admission_signal'])
                self.assertFalse(t.report_is_current(report,NOW))
                metrics=(root/'agents.prom').read_text()
                self.assertIn('agent_export_available 0',metrics)
                self.assertIn('agent_admission_signal 0',metrics)
                self.assertNotIn('agent_admission_signal 1',metrics)
                self.assertNotIn('agent_tasks{',metrics)

    def test_output_success_then_unreadable_cursor_invalidates(self):
        with tempfile.TemporaryDirectory(prefix='f17-cursor-') as directory:
            root=Path(directory);source=root/'snapshot.json';source.write_text(json.dumps(snapshot()))
            self.assertEqual(self.run_cli(source,root).returncode,0)
            self.assertEqual(self.run_cli(source,root,root/'missing-cursor.json').returncode,2)
            self.assertFalse(json.loads((root/'agents.json').read_text())['export_available'])

    def test_report_consumer_checks_current_time_not_frozen_age(self):
        data=snapshot()
        for task in data['tasks']:
            if task['state'] in t.CRITICAL_EVIDENCE_STATES:task['evidence_at']=data['observed_at']
            if task['state']=='RUNNING':task['lease_until']='2026-10-25T12:05:00Z'
        report=t.render(data,NOW)
        self.assertTrue(t.report_is_current(report,NOW))
        self.assertFalse(t.report_is_current(report,'2026-10-25T12:04:00Z'))
        self.assertFalse(t.report_is_current(report,report['valid_until']))
        metrics=t.prometheus(report)
        self.assertIn('agent_export_timestamp_seconds ',metrics)
        self.assertIn('agent_export_valid_until_timestamp_seconds ',metrics)
        self.assertIn('agent_snapshot_observed_timestamp_seconds ',metrics)

    def test_tiny_reservation_exceeds_cap_under_any_decimal_precision(self):
        for precision in (2,28,80):
            for swapped in (False,True):
                with self.subTest(precision=precision,swapped=swapped),localcontext() as context:
                    context.prec=precision
                    data=snapshot();data['dispatch_inputs']['total_spend_usd']=1
                    pair=('1.00','0.'+'0'*29+'1')
                    if swapped:pair=pair[::-1]
                    data['accounting']['api_spent_usd'],data['accounting']['api_reserved_usd']=pair
                    report=t.render(data,NOW)
                    self.assertIn('api_budget_exceeded',report['admission_hold_reasons'])
                    self.assertFalse(report['admission_signal'])

    def test_exact_equal_and_below_budget_do_not_round_up(self):
        for precision in (2,28,80):
            with localcontext() as context:
                context.prec=precision
                data=snapshot();data['dispatch_inputs']['total_spend_usd']=1
                data['accounting']['api_spent_usd']='0.'+'9'*30
                data['accounting']['api_reserved_usd']='0.'+'0'*29+'1'
                self.assertNotIn('api_budget_exceeded',t.render(data,NOW)['admission_hold_reasons'])
                data['accounting']['api_reserved_usd']='0.00'
                self.assertNotIn('api_budget_exceeded',t.render(data,NOW)['admission_hold_reasons'])

    def test_partial_output_replacement_does_not_leave_previous_positive(self):
        import export_snapshot as exporter
        with tempfile.TemporaryDirectory(prefix='f17-replace-') as directory:
            root=Path(directory);write_reports(root,t.render(snapshot(),NOW))
            original=exporter.os.replace;calls=[]
            def failing_replace(source,target):
                calls.append(target)
                if len(calls)==2:raise OSError('synthetic publication failure')
                return original(source,target)
            with patch.object(exporter.os,'replace',side_effect=failing_replace),self.assertRaises(OSError):
                write_reports(root,t.render(snapshot(),NOW))
            self.assertFalse((root/'agents.json').exists());self.assertFalse((root/'agents.prom').exists())
    def test_bounded_deep_json_is_rejected_without_raw_reader_error(self):
        with tempfile.TemporaryDirectory(prefix='f17-deep-') as directory:
            path=Path(directory)/'deep.json'
            for depth in (t.MAX_JSON_DEPTH+1,2000):
                nested='['*depth+'"synthetic-deep-secret"'+']'*depth
                self.assertLess(len(nested.encode()),t.MAX_BYTES)
                path.write_text(nested)
                with self.assertRaisesRegex(ValueError,'input nesting exceeds supported depth'):
                    t.read_snapshot(path)
            path.write_text('['*t.MAX_JSON_DEPTH+'0'+']'*t.MAX_JSON_DEPTH)
            self.assertIsInstance(t.read_snapshot(path),list)
            # Structural tokens in strings, including escaped quotes, are not depth.
            ordinary={'text':'['*2000+'escaped " quote and backslash \\'+']'*2000}
            for encoding in ('utf-8','utf-16'):
                path.write_text(json.dumps(ordinary),encoding=encoding)
                self.assertEqual(t.read_snapshot(path),ordinary)
    def test_deep_json_cli_redacts_and_replaces_success_for_both_output_modes(self):
        for prometheus in (False,True):
            with self.subTest(prometheus=prometheus),tempfile.TemporaryDirectory(prefix='f17-deep-cli-') as directory:
                root=Path(directory);source=root/'synthetic-private-deep.json'
                source.write_text(json.dumps(snapshot()))
                self.assertEqual(self.run_cli(source,root).returncode,0)
                source.write_text('['*(t.MAX_JSON_DEPTH+1)+'"synthetic-deep-secret"'+']'*(t.MAX_JSON_DEPTH+1))
                command=[sys.executable,'-B',str(Path(__file__).with_name('export_snapshot.py')),str(source),'--now',NOW,'--output-dir',str(root)]
                if prometheus:command.append('--prometheus')
                result=subprocess.run(command,capture_output=True,text=True,timeout=15)
                self.assertEqual(result.returncode,2)
                for forbidden in ('Traceback','synthetic-deep-secret','synthetic-private-deep',str(root)):
                    self.assertNotIn(forbidden,result.stdout+result.stderr)
                report=json.loads((root/'agents.json').read_text())
                self.assertEqual(report['status'],'INVALID_SNAPSHOT')
                self.assertFalse(report['export_available']);self.assertFalse(report['admission_signal'])
                self.assertFalse(report['dispatch_authorized'])
                metrics=(root/'agents.prom').read_text()
                self.assertIn('agent_export_available 0',metrics);self.assertNotIn('agent_admission_signal 1',metrics)
                if prometheus:self.assertIn('agent_export_available 0',result.stdout)
                else:self.assertFalse(json.loads(result.stdout)['export_available'])

    def test_render_recursion_uses_redacted_unavailable_boundary(self):
        import export_snapshot as exporter
        with tempfile.TemporaryDirectory(prefix='f17-render-depth-') as directory:
            root=Path(directory);source=root/'snapshot.json';source.write_text(json.dumps(snapshot()))
            write_reports(root,t.render(snapshot(),NOW))
            arguments=['export_snapshot.py',str(source),'--now',NOW,'--output-dir',str(root)]
            output=io.StringIO()
            with patch.object(sys,'argv',arguments),patch.object(t,'render',side_effect=RecursionError('synthetic-private-recursion')),contextlib.redirect_stdout(output):
                self.assertEqual(exporter.main(),2)
            self.assertNotIn('synthetic-private-recursion',output.getvalue())
            self.assertNotIn('Traceback',output.getvalue())
            self.assertFalse(json.loads((root/'agents.json').read_text())['export_available'])
            self.assertIn('agent_export_available 0',(root/'agents.prom').read_text())
if __name__=='__main__':unittest.main(verbosity=2)


