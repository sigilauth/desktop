# Mnemonic Domain — Recovery Phrase Generation and Verification
# English source strings — authored by @cora per voice guide §3-4
# Key naming: mnemonic-* for generation flow
# Note: BIP39 words themselves are NOT translated (English standard per i18n spec §8)

## Mnemonic Generation
# Context: Hardware RNG generating 24-word recovery phrase

mnemonic-title = Recovery Phrase
mnemonic-instructions = Write down these 24 words in order. Keep them safe and secret.
mnemonic-warning = Anyone with these words can access your account. Never share them.
mnemonic-screenshot-blocked = Screenshots are disabled for security.

## Word Display
# Context: Showing words in batches (screenshot-protected)

mnemonic-words-title = Your Recovery Phrase
mnemonic-word-number = Word { $number }
mnemonic-words-batch = Words { $start } - { $end }
mnemonic-show-next = Show Next Words
mnemonic-show-previous = Show Previous Words

## Write-Down Verification
# Context: User confirms they wrote down the words correctly

mnemonic-verify-title = Verify Your Recovery Phrase
mnemonic-verify-instructions = Enter these words to confirm you wrote them down correctly.
mnemonic-verify-word = Word #{ $number }
mnemonic-verify-submit = Verify
mnemonic-verify-success = Recovery phrase verified
mnemonic-verify-failed = Incorrect word. Check your written phrase and try again.

## Two-Phase Verification
# Context: Verification code matching between app and server

mnemonic-code-title = Verification Code
mnemonic-code-instructions = Confirm this code matches what the setup page shows.
mnemonic-code-label = Verification code
mnemonic-code-match-question = Does this code match?
mnemonic-code-confirmed = Yes, Confirmed
mnemonic-code-mismatch = No, Cancel

## Encrypted Delivery
# Context: Mnemonic being sent to server

mnemonic-sending = Sending encrypted recovery phrase...
mnemonic-sent = Recovery phrase sent securely
mnemonic-send-failed = Failed to send recovery phrase. Try again.

## Security Reminders
# Context: Warning messages during mnemonic flow

mnemonic-security-reminder = This is the only time these words will be shown.
mnemonic-offline-warning = Go offline before writing down your recovery phrase.
mnemonic-storage-advice = Store in a secure location. Consider multiple copies in different places.
