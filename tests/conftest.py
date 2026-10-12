import pytest

from beacon.protocol import ControlIE, DataIE, Fragment


@pytest.fixture
def control():
    return ControlIE(1, 2, 3, 1, 1)


@pytest.fixture
def fragment(control):
    return Fragment(control, DataIE(b"Hi"))
