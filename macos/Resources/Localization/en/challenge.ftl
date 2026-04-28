# Challenge Domain — Approval Screens for Auth and Step-Up
# English source strings — authored by @cora per voice guide §3-4
# Key naming: kebab-case, grouped by challenge type

## Generic Challenge
# Context: Push notification arrives, user opens app to approve

challenge-notification-title = { $serverName }
challenge-notification-body = Approval requested
challenge-approve = Approve
challenge-deny = Deny

## Challenge Details Screen
# Context: Full-screen approval with action context

challenge-from-server = { $serverName } requests approval
challenge-action-type = Action: { $actionType }
challenge-action-description = { $actionDescription }
challenge-requested = Requested: { $timeAgo }
# Plural selector for expiry countdown — CLDR categories required
challenge-expires = { $minutes ->
    [one] Expires in { $minutes } minute
   *[other] Expires in { $minutes } minutes
}

## Step-Up Authentication
# Context: Action-scoped challenge with specific parameters
# Developer note: users MUST see what they're approving — security critical

step-up-title = Approve: { $actionDescription }
step-up-for-user = For user: { $userEmail }
step-up-key-name = Key name: { $keyName }
step-up-resource = Resource: { $resourceId }

## Challenge States
# Context: Status indicators during challenge lifecycle

challenge-state-pending = Waiting for approval
challenge-state-approved = Approved
challenge-state-denied = Denied
challenge-state-expired = Expired

## Offline Handling
# Context: Device received challenge but may be offline

challenge-offline-warning = You appear to be offline. Connect to respond.
challenge-retry-connection = Retry Connection
