# Rotating a room’s shared-file key

Only the room owner can rotate the shared-file key, and only while the room is open. In **Shared room files**, choose **Rotate shared-file key** and confirm. Portkey creates the replacement key in the browser and sends the server only its fingerprint and a history bundle encrypted for the replacement key.

After rotation, send the updated room invitation to participants who should keep access. It includes the new shared-file key. A participant who opens it can decrypt completed files from earlier key epochs and files uploaded after the rotation. A browser still using an older invitation can access files for which it already has a matching key, but it cannot decrypt new files; it will ask for an updated invitation. Old invitations do not gain the new key automatically.

Completed file ciphertext is not re-encrypted. Each file stays bound to the key fingerprint used when it was prepared. Rotation deletes unfinished server uploads, including their reserved storage. Local prepared plans encrypted under the retired key remain in the browser, but cannot be shared under the new key. Select the original file again to encrypt a fresh copy with a new file ID and nonce. Legacy plans that do not record a key fingerprint are kept for recovery or discard and cannot be uploaded until the file is selected again.

The browser atomically reserves a rotation candidate before sending the request. Another tab cannot replace that candidate, and a delayed response cannot replace a key from a newer epoch. If another organizer tab changes the key first, reload the room before retrying. If the response is lost, it checks the server’s current fingerprint and encrypted history; after a reload it can recover the candidate from local storage when the server confirms that rotation committed. It validates the history before replacing the cached key. If browser storage cannot commit the new key and history together, the old cache remains and the candidate stays pending for recovery.

A room supports at most 32 key epochs, including the current key. The encrypted history bundle is capped at 31 earlier keys. Once the room reaches the limit, create another room to use another shared-file key.

Shared-file key rotation does not change the private inbox key or private submissions. It also does not revoke a participant’s room membership. Remove that participant separately to block future API access. Neither rotation nor revocation can retract a key or file already received or downloaded.
