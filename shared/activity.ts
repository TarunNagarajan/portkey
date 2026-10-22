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
  | 'submission_cleanup_enabled'
  | 'submissions_purged'
  | 'admission_passes_issued'
  | 'pass_revoked'
  | 'pass_redeemed';

export type RoomField = 'title' | 'description' | 'expiresAt' | 'admissionPolicy';

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
