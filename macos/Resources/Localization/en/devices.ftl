# Devices Domain — Device and Server Management
# English source strings — authored by @cora per voice guide §3-4
# Key naming: kebab-case, grouped by management flow

## Device Info
# Context: Viewing own device details

device-info-title = Device Info
device-name = Device name
device-name-placeholder = My iPhone
device-model = Model
device-os = Operating system
device-registered = Registered
device-last-auth = Last authentication

## Device Fingerprint Display
# Context: Showing fingerprint for verification
# Developer note: pictogram + speakable form for verbal verification

device-fingerprint-title = Device Fingerprint
device-pictogram-label = Your device pictogram
device-speakable-hint = Say this to verify: { $speakable }
device-fingerprint-hex = Fingerprint
device-copy-fingerprint = Copy
device-share-fingerprint = Share

## Device Count
# Context: Summary showing number of registered devices
# Plural selector — CLDR categories required for ar (6), pl (4), ru (4)

devices-count = { $count ->
    [zero] No devices registered
    [one] { $count } device registered
    [two] { $count } devices registered
    [few] { $count } devices registered
    [many] { $count } devices registered
   *[other] { $count } devices registered
}

## Server List
# Context: Managing multiple server connections

server-list-title = Registered Servers
server-add = Add Server
server-count = { $count ->
    [zero] No servers
    [one] { $count } server
    [two] { $count } servers
    [few] { $count } servers
    [many] { $count } servers
   *[other] { $count } servers
}

## Empty States
# Context: No content yet — per voice guide §4.7

servers-empty-title = No servers yet
servers-empty-body = Scan a QR code or enter a pairing code to register with a server.
servers-empty-action = Add Server

activity-empty-title = All quiet
activity-empty-body = Approval requests will appear here.

## Server Details
# Context: Viewing individual server info

server-name = Server name
server-url = Server URL
server-registered = Connected since
server-last-challenge = Last request

## Remove Device
# Context: Removing server connection from device

device-remove = Remove Device
device-remove-title = Remove Device?
device-remove-body = This will delete the local key. You will need to re-register with this server.
device-remove-confirm = Remove
device-remove-cancel = Cancel

## Remove Server
# Context: Disconnecting from a server

server-remove = Remove Server
server-remove-title = Remove { $serverName }?
server-remove-body = You will need to re-register to use this server again.
server-remove-confirm = Remove
server-remove-cancel = Cancel
