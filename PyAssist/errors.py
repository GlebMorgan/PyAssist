import struct

from Utils import alias


__all__ = 'StructParseError', 'DeviceError', 'BadAckError', 'DataInvalidError', 'AppError', 'SignatureError'


StructParseError = alias(struct.error)
StructParseError.__doc__ = """ Failed to parse device reply packet """


class DataError():
    def __init__(self, *args, **kwargs):
        super().__init__(*args)
        self.__dict__.update(kwargs)


class DeviceError(RuntimeError):
    """ Device-side error, probable command handling misoperation """


class BadAckError(DataError, DeviceError):
    """ Devise has sent 'FF' acknowledge byte => error executing command on device side """


class DataInvalidError(DataError, DeviceError):
    """ Device reply contains invalid data """


class AppError(RuntimeError):
    """ Application-level error """


class SignatureError(AppError):
    """ Invalid PyAssist API call signature """
