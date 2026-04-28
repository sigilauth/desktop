# Common Domain — Shared UI Strings
# English source strings — authored by @cora per voice guide §3-4
# Key naming: btn-* for buttons, a11y-* for accessibility, time-* for relative time

## Buttons
# Context: Reusable button labels

btn-continue = Continue
btn-cancel = Cancel
btn-done = Done
btn-copy = Copy
btn-share = Share
btn-retry = Retry
btn-save = Save
btn-delete = Delete
btn-confirm = Confirm
btn-back = Back
btn-next = Next
btn-close = Close
btn-ok = OK
btn-yes = Yes
btn-no = No

## States
# Context: Loading, empty, success, and error states
# Per voice guide §2: success states are "warm, brief"

loading = Loading...
loading-with-context = Loading { $context }...
empty-state = Nothing here yet
success-generic = Done
success-all-set = Done. You're all set.
error-title = Error
error-generic = Something went wrong. Please try again.

## Relative Time
# Context: "X minutes ago" style timestamps
# Plural selectors — CLDR categories required

time-just-now = Just now
time-seconds-ago = { $count ->
    [one] { $count } second ago
   *[other] { $count } seconds ago
}
time-minutes-ago = { $count ->
    [one] { $count } minute ago
   *[other] { $count } minutes ago
}
time-hours-ago = { $count ->
    [one] { $count } hour ago
   *[other] { $count } hours ago
}
time-days-ago = { $count ->
    [one] { $count } day ago
   *[other] { $count } days ago
}
time-weeks-ago = { $count ->
    [one] { $count } week ago
   *[other] { $count } weeks ago
}

## Countdown
# Context: Expiry countdowns (challenges, codes)

countdown-minutes = { $count ->
    [one] { $count } minute remaining
   *[other] { $count } minutes remaining
}
countdown-seconds = { $count ->
    [one] { $count } second remaining
   *[other] { $count } seconds remaining
}
countdown-expired = Expired

## Accessibility Labels
# Context: Screen reader labels (a11y-* prefix)

a11y-close-button = Close
a11y-back-button = Go back
a11y-loading = Loading content
a11y-pictogram = Device pictogram showing { $speakable }
a11y-fingerprint = Device fingerprint { $fingerprint }
a11y-copy-success = Copied to clipboard
a11y-server-pictogram = Server pictogram showing { $speakable }

## Clipboard
# Context: Copy to clipboard feedback

clipboard-copied = Copied
clipboard-copy-failed = Copy failed

## Network
# Context: Network status indicators

network-offline = You are offline
network-reconnecting = Reconnecting...
network-connected = Connected
