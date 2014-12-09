from DenyHosts.util import is_true

def test_is_true():
    for string in ['1', 't', 'true', 'y', 'yes']:
        assert is_true(string)

    for string in ['', 'false', 'ye', 'tr']:
        assert not is_true(string)
