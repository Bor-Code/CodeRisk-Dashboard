class ApplicationError(Exception):
    code = "application_error"
    status_code = 500
    title = "Application error"

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


class InvalidTargetError(ApplicationError):
    code = "invalid_target"
    status_code = 400
    title = "Invalid scan target"


class ResourceNotFoundError(ApplicationError):
    code = "not_found"
    status_code = 404
    title = "Resource not found"


class ScanExecutionError(ApplicationError):
    code = "scan_failed"
    status_code = 500
    title = "Scan failed"
