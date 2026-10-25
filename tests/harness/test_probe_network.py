"""No network: every socket factory and connection is mocked."""
import contextlib
import errno
import io
import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch
import probe_network as probe


class ProbeTests(unittest.TestCase):
    def run_probe(self,factory,flag=True,environment=True):
        argv=['probe_network.py']+(['--probe-test-net'] if flag else [])
        env={'F07_NETWORK_NAMESPACE_EXPECTED':'1'} if environment else {}
        output=io.StringIO()
        with patch.object(sys,'argv',argv),patch.dict(os.environ,env,clear=True),patch.object(probe.socket,'socket',factory),contextlib.redirect_stdout(output):
            code=probe.main()
        return code,json.loads(output.getvalue())

    def test_both_opt_in_conditions_are_required_without_socket_creation(self):
        for flag,environment in ((False,False),(False,True),(True,False)):
            factory=MagicMock(side_effect=AssertionError('socket must not be created'))
            code,result=self.run_probe(factory,flag,environment)
            self.assertEqual(code,2);self.assertEqual(result['status'],'NOT_RUN');factory.assert_not_called()

    def test_creation_policy_denial_is_structured_and_does_not_echo_error(self):
        for error in (errno.EPERM,errno.EACCES,errno.ENETUNREACH,errno.EHOSTUNREACH):
            factory=MagicMock(side_effect=OSError(error,'synthetic-private-error'))
            code,result=self.run_probe(factory)
            self.assertEqual(code,0);self.assertEqual(result['status'],'DENY_OBSERVED')
            self.assertEqual(result['phase'],'socket_creation');self.assertEqual(result['errno'],error)
            self.assertNotIn('synthetic-private-error',str(result))

    def test_timeout_setup_policy_denial_is_structured_and_never_connects(self):
        for error in (errno.EPERM,errno.EACCES,errno.ENETUNREACH,errno.EHOSTUNREACH):
            connection=MagicMock();connection.__enter__.return_value=connection
            connection.settimeout.side_effect=OSError(error,'synthetic-private-error')
            code,result=self.run_probe(MagicMock(return_value=connection))
            self.assertEqual(code,0);self.assertEqual(result['status'],'DENY_OBSERVED')
            self.assertEqual(result['phase'],'timeout_setup');connection.connect.assert_not_called()
            connection.__exit__.assert_called_once()

    def test_other_creation_or_setup_errors_remain_inconclusive(self):
        code,result=self.run_probe(MagicMock(side_effect=OSError(errno.EMFILE,'synthetic-resource-error')))
        self.assertEqual(code,2);self.assertEqual(result['status'],'INCONCLUSIVE')
        connection=MagicMock();connection.__enter__.return_value=connection
        connection.settimeout.side_effect=OSError(errno.EINVAL,'synthetic-setup-error')
        code,result=self.run_probe(MagicMock(return_value=connection))
        self.assertEqual(code,2);self.assertEqual(result['status'],'INCONCLUSIVE')
        connection.connect.assert_not_called()

    def test_connect_errno_classification_is_preserved(self):
        for error,code_expected,status in ((errno.EPERM,0,'DENY_OBSERVED'),(errno.EACCES,0,'DENY_OBSERVED'),(errno.ENETUNREACH,0,'DENY_OBSERVED'),(errno.EHOSTUNREACH,0,'DENY_OBSERVED'),(errno.ECONNREFUSED,2,'INCONCLUSIVE')):
            connection=MagicMock();connection.__enter__.return_value=connection
            connection.connect.side_effect=OSError(error,'synthetic-connect-error')
            code,result=self.run_probe(MagicMock(return_value=connection))
            self.assertEqual(code,code_expected);self.assertEqual(result['status'],status)
            self.assertEqual(result['phase'],'connect')
            connection.settimeout.assert_called_once_with(2)
            connection.connect.assert_called_once_with(('192.0.2.1',9))

    def test_successful_connection_is_deny_failed(self):
        connection=MagicMock();connection.__enter__.return_value=connection
        code,result=self.run_probe(MagicMock(return_value=connection))
        self.assertEqual(code,1);self.assertEqual(result['status'],'DENY_FAILED')

    def test_close_error_cannot_hide_successful_connection(self):
        connection=MagicMock();connection.__enter__.return_value=connection
        connection.__exit__.side_effect=OSError(errno.EPERM,'synthetic-close-error')
        code,result=self.run_probe(MagicMock(return_value=connection))
        self.assertEqual(code,1);self.assertEqual(result['status'],'DENY_FAILED')


if __name__=='__main__':unittest.main(verbosity=2)
