import { z } from 'zod';

export const roomInput = z
  .object({
    title: z.string().trim().min(1).max(100),
    description: z.string().trim().max(500).default(''),
    expiresAt: z.iso.datetime({ offset: true }),
  })
  .strict();

export const roomTemplateInput = roomInput.extend({
  title: roomInput.shape.title.optional(),
  description: roomInput.shape.description.removeDefault().optional(),
});

export const roomId = z.uuid();
export const joinCode = z.string().regex(/^[A-Za-z0-9_-]{16}$/);
export const memberDecision = z
  .object({
    status: z.enum(['approved', 'denied', 'revoked']),
  })
  .strict();

export type RoomInput = z.infer<typeof roomInput>;
export type RoomStatus = 'draft' | 'open' | 'closed' | 'expired';
export type MembershipStatus = 'pending' | 'approved' | 'denied' | 'revoked';

export interface Room {
  id: string;
  title: string;
  description: string;
  status: RoomStatus;
  expiresAt: string;
  createdAt: string;
  role: 'owner' | 'participant';
  membershipStatus: MembershipStatus | null;
  joinCode: string;
  submissionCleanupEnabled: boolean;
  submissionsPurgedAt: string | null;
}

export interface PublicRoom {
  id: string;
  title: string;
  description: string;
  status: RoomStatus;
  expiresAt: string;
  membershipStatus: MembershipStatus | null;
  isOwner: boolean;
  organizerKeyFingerprint: string | null;
  organizerPublicKey: string | null;
  submissionCleanupEnabled: boolean;
  submissionsPurgedAt: string | null;
}

export interface Member {
  id: string;
  label: string;
  status: MembershipStatus;
  requestedAt: string;
}
