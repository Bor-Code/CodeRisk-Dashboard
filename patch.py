import re

with open('backend/app/repositories/scans.py', 'r') as f:
    content = f.read()

# 1. Update imports
content = content.replace('from app.domain.entities import (', 'from app.domain.entities import (\n    ClaimedScan,')
content = content.replace('from app.domain.reports import FindingCategory, RepoMetadata, ScanReport, Severity', 'from app.domain.reports import FindingCategory, RepoMetadata, ScanReport, Severity\nfrom app.jobs.errors import LostScanLeaseError\nfrom datetime import timedelta')

# 2. Update begin_scan
content = content.replace('status="running"', 'status="pending"')

# 3. Add worker_id to complete_scan and fail_scan
content = content.replace('def complete_scan(self, scan_id: str, report: ScanReport) -> PersistedScan:', 'def complete_scan(self, scan_id: str, report: ScanReport, worker_id: str | None = None) -> PersistedScan:')
content = content.replace('def fail_scan(self, scan_id: str, error_message: str) -> ScanSummary:', 'def fail_scan(self, scan_id: str, error_message: str, worker_id: str | None = None) -> ScanSummary:')

def insert_check(method_content, match_str):
    check = '''        if worker_id is not None and model.worker_id != worker_id:
            raise LostScanLeaseError()
'''
    return method_content.replace(match_str, match_str + '\n' + check)

content = insert_check(content, 'model = self._get_scan_model(scan_id)\n        completed_at = utc_now()')

# 4. Append new methods to ScanStore
new_methods = '''
    def claim_next_scan(self, worker_id: str, lease_seconds: int, max_attempts: int) -> ClaimedScan | None:
        now = utc_now()
        statement = (
            select(ScanModel)
            .where(
                ScanModel.status == "pending",
                (ScanModel.lease_expires_at.is_(None)) | (ScanModel.lease_expires_at < now),
                ScanModel.attempt_count < max_attempts
            )
            .order_by(ScanModel.created_at.asc())
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        model = self.session.scalar(statement)
        if not model:
            return None
            
        model.worker_id = worker_id
        model.lease_expires_at = now + timedelta(seconds=lease_seconds)
        model.attempt_count += 1
        model.status = "running"
        model.started_at = now
        
        for er in model.engine_runs:
            if er.status == "pending":
                er.status = "running"
                er.started_at = now
                
        self.session.flush()
        return ClaimedScan(id=model.id, worker_id=worker_id, target=model.repository.target)

    def renew_lease(self, scan_id: str, worker_id: str, lease_seconds: int) -> bool:
        model = self.session.get(ScanModel, scan_id)
        if not model or model.worker_id != worker_id or model.status != "running":
            return False
        model.lease_expires_at = utc_now() + timedelta(seconds=lease_seconds)
        self.session.flush()
        return True

    def cancellation_requested(self, scan_id: str, worker_id: str) -> bool:
        model = self.session.get(ScanModel, scan_id)
        if not model or model.worker_id != worker_id:
            return False
        return model.cancellation_requested_at is not None

    def cancel_claimed_scan(self, scan_id: str, worker_id: str) -> None:
        model = self.session.get(ScanModel, scan_id)
        if not model or model.worker_id != worker_id:
            raise LostScanLeaseError()
        model.status = "cancelled"
        model.completed_at = utc_now()
        self.session.flush()

    def recover_expired_scans(self, max_attempts: int) -> None:
        now = utc_now()
        statement = select(ScanModel).where(
            ScanModel.status == "running",
            ScanModel.lease_expires_at < now,
            ScanModel.attempt_count >= max_attempts
        )
        models = self.session.scalars(statement).all()
        for model in models:
            model.status = "failed"
            model.error_message = "Scan failed after maximum attempts due to worker timeout."
            model.completed_at = now
            for er in model.engine_runs:
                if er.status == "running":
                    er.status = "failed"
                    er.error_message = "Worker timeout."
                    er.completed_at = now
        self.session.flush()
'''

content = content.replace('    def _scan_detail_statement() -> Select:', new_methods + '\n    def _scan_detail_statement() -> Select:')

with open('backend/app/repositories/scans.py', 'w') as f:
    f.write(content)
