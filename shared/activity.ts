export type ActivityKind =
  | 'room_created'
  | 'room_duplicated'
  | 'room_updated'
  | 'room_opened'
  | 'room_closed'
  | 'join_requested'
  | 'member_approved'
  | 'member_denied'
  | 'member_revoked'
  | 'key_registered'
  | 'file_published'
  | 'files_purged'
  | 'credential_proved'
  | 'key_rotated' | 'file_access_granted' | 'ownership_recovered' | 'file_deleted';

export type RoomField = 'title' | 'description' | 'expiresAt' | 'credential';

export interface ActivityEvent {
  id: string;
  kind: ActivityKind;
  memberLabel: string | null;
  changedFields: RoomField[];
  createdAt: string;
}

export interface ActivityPage {
  events: ActivityEvent[];
  nextCursor: string | null;
}
