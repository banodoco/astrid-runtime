"""Conservative accounting only; no test here establishes writer authority."""
import threading

import pytest

from runtime_protocol.transfer_delivery_accounting import AccountingError, DeliveryAccounting


def request(**updates):
    value = {'operation_id': 'op', 'generation': 'gen', 'request_id': 'req',
             'expected_phase': 'prepared', 'binding_digest': 'a' * 64,
             'sequence': 1, 'role': 'candidate'}
    value.update(updates)
    return value


def ledger():
    return DeliveryAccounting(operation_id='op', generation='gen', binding_digest='a' * 64)


def test_replay_does_not_authorize_a_second_send_and_mutation_is_rejected():
    accounting = ledger()
    original = request()
    assert accounting.mark_before_send(original) == 'recorded'
    original['role'] = 'migration'
    with pytest.raises(AccountingError, match='binding_changed'):
        accounting.mark_before_send(original)
    assert accounting.mark_before_send(request()) == 'replay'
    with pytest.raises(AccountingError, match='lease_uncertain'):
        accounting.mark_before_send(request(request_id='another'))
    assert accounting.status() == 'lease_uncertain'


@pytest.mark.parametrize('changes', [
    {'operation_id': 'other'}, {'generation': 'other'}, {'binding_digest': 'b' * 64},
    {'sequence': True}, {'expected_phase': 'held_admitted'}, {'role': 'rollback-r0'},
    {'extra': 'unknown'}, {'request_id': ''}, {'role': []},
])
def test_bad_request_cannot_record_delivery(changes):
    accounting = ledger()
    with pytest.raises(AccountingError, match='binding_changed'):
        accounting.mark_before_send(request(**changes))
    assert accounting.status() == 'no_delivery_recorded'


def test_concurrent_delivery_attempts_leave_exactly_one_recorded():
    accounting = ledger()
    barrier = threading.Barrier(8)
    outcomes = []
    def attempt(index):
        barrier.wait()
        try:
            outcomes.append(accounting.mark_before_send(request(request_id=str(index))))
        except AccountingError as exc:
            outcomes.append(str(exc))
    threads = [threading.Thread(target=attempt, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert outcomes.count('recorded') == 1
    assert outcomes.count('lease_uncertain') == 7
    assert accounting.status() == 'lease_uncertain'
