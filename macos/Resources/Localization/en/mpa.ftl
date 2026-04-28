# MPA Domain — Multi-Party Authorization
# English source strings — authored by @cora per voice guide §3-4
# Key naming: kebab-case, grouped by MPA flow
# Note: Per D7, MPA user-strings MUST NOT abbreviate "Multi-Party Authorization"

## MPA Request Notification
# Context: Push notification for MPA request

mpa-notification-title = Approval Required
mpa-notification-body = { $serverName } requests approval for { $actionDescription }

## MPA Approval Screen
# Context: Full-screen MPA approval with progress
# Note: Per D7, avoid "Multi-Party Authorization" jargon — use plain contextual language

mpa-request-title = Approval Required
mpa-action = { $serverName } requests approval for { $actionDescription }
# Plural selector for approval progress — use cardinal, not ordinal
mpa-progress = { $approved ->
    [one] { $approved } of { $required } approvals received
   *[other] { $approved } of { $required } approvals received
}
mpa-waiting-for-more = { $remaining ->
    [one] Waiting for { $remaining } more approval
   *[other] Waiting for { $remaining } more approvals
}
mpa-your-approval = Your approval is one of { $required } needed

## MPA Status
# Context: Status indicators for MPA request

mpa-status-pending = Pending
mpa-status-approved = Approved
mpa-status-rejected = Rejected
mpa-status-expired = Expired
mpa-status-timeout = Timed out

## Group Notifications
# Context: When another device in user's group approves

mpa-your-group-approved = Your group has approved
mpa-waiting-others = Waiting for other approvers
mpa-clear-notification = No action needed
mpa-clear-explanation = Another device in your group has already approved this request.

## MPA Rejection
# Context: User explicitly rejects MPA request

mpa-reject-confirm-title = Reject Request?
mpa-reject-confirm-body = Are you sure you want to reject this authorization request?
mpa-reject-button = Reject
mpa-rejected-confirmation = Request rejected

## MPA Quorum
# Context: Quorum reached, action proceeding

mpa-quorum-reached = Authorization complete
mpa-quorum-explanation = { $approved } of { $required } required approvals received. Action proceeding.
