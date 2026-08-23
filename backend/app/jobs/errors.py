class ScanJobError(Exception):
    pass


class InvalidScanTargetError(ScanJobError):
    pass


class ScanCancelledError(ScanJobError):
    pass


class ScanTimedOutError(ScanJobError):
    pass


class ScanResultTooLargeError(ScanJobError):
    pass


class ScanProcessError(ScanJobError):
    pass


class LostScanLeaseError(ScanJobError):
    pass
