import pickle

import pytest

import viv_utils

EXECUTED = []


def mark_executed():
    EXECUTED.append(True)


class Payload:
    def __reduce__(self):
        return (mark_executed, ())


def write_pickle_viv(path):
    with open(path, "wb") as f:
        f.write(b"VIV".ljust(8, b"\x00") + pickle.dumps([Payload()], protocol=2))


def write_msgpack_viv(path):
    with open(path, "wb") as f:
        f.write(b"\xa8MSGVIV\x00\x00")


@pytest.mark.parametrize("write", [write_pickle_viv, write_msgpack_viv])
def test_getWorkspace_rejects_workspace_without_viv_extension(tmp_path, write):
    path = tmp_path / "sample.exe_"
    write(str(path))

    EXECUTED.clear()
    with pytest.raises(viv_utils.UnsupportedFormatError):
        viv_utils.getWorkspace(str(path), should_save=False)
    assert not EXECUTED


@pytest.mark.parametrize("write", [write_pickle_viv, write_msgpack_viv])
def test_getWorkspaceFromFile_rejects_workspace(tmp_path, write):
    path = tmp_path / "sample.exe_"
    write(str(path))

    EXECUTED.clear()
    with pytest.raises(viv_utils.UnsupportedFormatError):
        viv_utils.getWorkspaceFromFile(str(path), analyze=False)
    assert not EXECUTED


def test_guessInputFormat():
    from fixtures import DATA

    assert viv_utils.guessInputFormat(str(DATA / "Practical Malware Analysis Lab 01-01.dll_")) == "pe"
