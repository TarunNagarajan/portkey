"""Rebuild current report and 14-slide presentation PDFs from checked-in evidence."""
from pathlib import Path
import json, shutil
from html import escape
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle, Image, Flowable
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'docs'; OUT.mkdir(exist_ok=True)
FONT='/usr/share/fonts/noto/NotoSans-Regular.ttf'
BOLD='/usr/share/fonts/noto/NotoSans-Bold.ttf'
pdfmetrics.registerFont(TTFont('Noto', FONT)); pdfmetrics.registerFont(TTFont('NotoBold',BOLD))
INK=colors.HexColor('#333231'); MUTED=colors.HexColor('#5b5854'); ACCENT=colors.HexColor('#5c6b54'); BG=colors.HexColor('#eeecea')
styles=getSampleStyleSheet()
for name in ['Normal','BodyText','Heading1','Heading2','Title']:
 styles[name].fontName='Noto'; styles[name].textColor=INK
styles['BodyText'].fontSize=10; styles['BodyText'].leading=15; styles['BodyText'].spaceAfter=9
styles['Title'].fontSize=32; styles['Title'].leading=38
styles['Heading1'].fontSize=22; styles['Heading1'].leading=28; styles['Heading1'].spaceAfter=15
styles['Heading2'].fontSize=13; styles['Heading2'].leading=18; styles['Heading2'].spaceBefore=10
small=ParagraphStyle('Small',parent=styles['BodyText'],fontSize=8,leading=12)
bench=json.loads((ROOT/'benchmark-results/250-mib.json').read_text())
load=json.loads((ROOT/'benchmark-results/postgres-load.json').read_text())
evidence=json.loads((ROOT/'docs/evidence.json').read_text())
def para(text,style='BodyText'): return Paragraph(text,styles[style])
class CroppedScreenshot(Flowable):
 def __init__(self,path,width,height):
  Flowable.__init__(self);self.path=path;self.width=width;self.height=height
 def draw(self):
  from PIL import Image as PILImage
  w,h=PILImage.open(self.path).size;scaledh=h*self.width/w
  self.canv.saveState();clip=self.canv.beginPath();clip.rect(0,0,self.width,self.height);self.canv.clipPath(clip,stroke=0)
  self.canv.drawImage(str(self.path),0,self.height-scaledh,width=self.width,height=scaledh,mask='auto');self.canv.restoreState()
def image(path,width,maxheight):
 if not path.exists(): return Spacer(1,1)
 return CroppedScreenshot(path,width,maxheight)
def table(rows,widths):
 rows=[[Paragraph(escape(str(cell)),small) for cell in row] for row in rows]
 t=Table(rows,colWidths=widths,hAlign='LEFT');t.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'TOP'),('BACKGROUND',(0,0),(-1,0),colors.HexColor('#e4e1dd')),('BOTTOMPADDING',(0,0),(-1,-1),8),('TOPPADDING',(0,0),(-1,-1),8),('LINEBELOW',(0,0),(-1,0),0.5,ACCENT)]));return t
def footer(c,doc):
 c.setFont('Noto',8);c.setFillColor(MUTED);c.drawString(42,25,'PORTKEY  /  IMPLEMENTATION EVIDENCE  /  1 NOVEMBER 2026');c.drawRightString(570,25,str(doc.page))
report=OUT/'Portkey_Implementation_and_Feature_Mapping_Report.pdf'
story=[]
def page(title,blocks):
 if story: story.append(PageBreak())
 story.append(para(title,'Heading1'));story.extend(blocks)
page('Portkey',[
 para('Zero-knowledge credential admission and encrypted room file sharing','Title'),Spacer(1,16),
 para('Full Stack Development project - implementation and feature mapping report'),
 para('Updated 1 November 2026. React and TypeScript in the browser. Express with PostgreSQL or PGlite on the server.'),
 image(ROOT.parent/'outputs/Portkey_SharedFiles_Desktop.png',528,285),Spacer(1,14),
 para('Scope: organizers distribute files to approved participants. Participant uploads are deliberately excluded. The repository includes operational tooling, automated tests and reproducible evidence.'),
 para('Readiness: the software paths below are implemented and locally verified. Institutional identity integration, independent ceremony participation, real-device acceptance and an external security review remain operator responsibilities.'),
])
page('Architecture and trust boundaries',[
 para('Browser: session UI, credential proof generation, HPKE key handling, AES-GCM content encryption, resumable upload journal and authenticated downloads.'),
 para('API: session and CSRF checks, room lifecycle, challenge consumption, proof verification, admission decisions, key/envelope policies, quotas, rate budgets and cleanup.'),
 para('Database: sessions, rooms, memberships, room activity, public recipient keys, ciphertext chunks/envelopes, credential challenges/revocations, one-time recovery hashes and shared rate windows.'),
 table([['Data','Browser','API/database'],['File name and contents','Plaintext during selection/decryption','Encrypted descriptor and chunks'],['Private decryption key','IndexedDB / passphrase-protected backup','Never uploaded'],['Credential secret and signature','Private proof inputs','Never uploaded by normal join flow'],['Eligibility proof','Generated locally','Proof and nine public signals'],['Location, labels, sizes and timings','Visible locally','Visible to service / organizer as authorized']], [140,190,198]),
 Spacer(1,12),para('A compromised server can serve altered JavaScript that steals browser secrets. This design protects stored content under the intended application, not against a malicious application origin. Browser location remains spoofable.'),
 para('Database-clock expiry and room locks make admission, publication and cleanup policies consistent. API responses use no-store caching; writes require Origin and CSRF checks. Issuer revocations use pinned-issuer signature authorization.'),
])
page('Credential proof protocol v2',[
 para('The issuer signs Poseidon(secret, department, class year, validUntil). The circuit proves signature possession and derives both a per-room nullifier and a binding to a fresh random session challenge.'),
 table([['Public signal','Purpose'],['nullifier','One credential seat per room'],['binding','Poseidon(secret, challenge) constrains the challenge in the circuit'],['issuerAx, issuerAy','Pinned institution public key'],['department, year','Eligibility requirement'],['scope','Room UUID interpreted as a field value'],['challenge','Random ten-minute value owned by the requesting session/room'],['validUntil','Signed credential expiry checked using server/database time']], [165,363]),
 Spacer(1,12),para('The server checks the pairing, issuer, attributes and scope, then checks the unconsumed session challenge, expiry and revocation under the room lock. Successful admission consumes the challenge atomically. A copied proof cannot front-run from a different browser session.'),
 para('Issuer-signed revocations publish separately scoped nullifiers for affected rooms and block both future joins and existing access. The supplied institution-side worker/timer applies that policy to affected current and future rooms on a schedule; there is no public cross-room credential identifier. The delivery interval remains a revocation-latency boundary.'),
 para('Migration 010 returns approved v1 credential memberships to pending. Operators must issue v2 credentials and deploy the matching wasm, zkey, verification key and checksum manifest together.'),
])
page('File encryption, resume and key management',[
 para('Each publication uses a fresh secret and salt. Separate HKDF-SHA256 labels derive AES-256-GCM content and metadata keys. One-MiB chunks use indexed nonces and context-bound authenticated data. HPKE P-256/HKDF-SHA256/AES-256-GCM seals the file key to each recipient.'),
 para('The server accepts immutable chunk retries and verifies a SHA-256 descriptor/chunk manifest on completion. Downloads authenticate every chunk and manifest before the final save. Receipts record server acceptance and are not independent signed attestations.'),
 table([['Capability','Implementation'],['250 MiB files','250 chunks, 1,000 files and 5 GiB encrypted chunk storage per room'],['Durable resume','Immutable source snapshot in OPFS or bounded 50 MiB memory-storage fallback; plan/chunks in IndexedDB'],['Nonce safety','Persist reservation before encryption and ciphertext before upload; abandon interrupted reservations'],['Late arrivals','Organizer grants new envelopes over existing ciphertext'],['Key rotation','Atomically rewrap every current envelope; reject stale keys or incomplete replacement sets'],['Ownership recovery','Separate one-time random recovery code transfers authority; encrypted key backup restores decryption'],['Deletion','Owner can delete completed files; expiry cleanup cascades ciphertext/envelopes/chunks']], [150,378]),
 Spacer(1,10),para('OPFS-unavailable browsers use bounded fallback behavior. Browser eviction can remove pending state. Rotation and revocation do not erase keys, ciphertext or plaintext already copied by a recipient.'),
])
page('Feature mapping and implementation files',[
 table([['Feature','Main implementation','Verification'],['Room lifecycle / approval','server/rooms.ts; client/RoomPage.tsx','API + mobile browser flows'],['Proof challenge and expiry','circuits/credential.circom; server/zk.ts','Real Groth16 proofs and replay/expiry cases'],['Institution revocation','server/issuerRoutes.ts; scripts/issuer.ts','Pinned issuer signature and revocation cases'],['Encrypted file distribution','server/roomFiles.ts; client/roomCrypto.ts','HPKE vector + browser decrypt/integrity'],['Resume / cancellation','client/uploadStore.ts; client/RoomFiles.tsx','Reload/resume and reserved-nonce faults'],['Recovery / rotation / grants','server/recovery.ts; server/keys.ts','API + ownership/decryption browser flow'],['Geofence','server/participantAccess.ts','Direct-route bypass regression'],['Shared rate budgets','server/rateStore.ts','Two-instance concurrency / PostgreSQL load probe'],['Operations / deployment','server/operations.ts; compose.yaml; deploy/','Metrics auth, restore probe, HTTPS smoke'],['Accessibility / compatibility','e2e/accessibility.spec.ts; compatibility.spec.ts','Axe serious/critical checks; browser matrix']], [132,225,171]),
 Spacer(1,12),para('Schema history: 001-006 establish rooms, history, historical submissions and geofencing. 007 adds room file distribution; 008 removes old submission tables; 009 adds credential gates; 010 adds challenge/expiry/revocation/recovery/shared budgets and privacy cleanup indexes.'),
 para('No applied historical migration was rewritten. Migration 010 is a new migration. The old submission data removal in migration 008 requires backup and an intentional upgrade decision.'),
])
page('Measured verification results',[
 table([['Check','Evidence'],['API, embedded PostgreSQL',f"{evidence['apiTests']} passing tests on PGlite"],['API, PostgreSQL 17',f"{evidence['postgresTests']} passing tests against a real PostgreSQL container"],['Browser workflows',evidence['browserSummary']],['Compatibility',evidence['compatibilitySummary']],['Production', 'Three real proof/key-lifecycle flows through built assets, HTTPS, secure cookies and CSP'],['Accessibility','Workspace, room and recovery form: no serious/critical Axe WCAG A/AA violations'],['Resilience','Offline/reconnect, no OPFS, quota failure and abandoned nonce reservation'],['Backup / restore','Migrated app tables and exact ciphertext bytes restored into a new database']], [170,358]),
 Spacer(1,15),para('250 MiB end-to-end transfer','Heading2'),
 para(f"262,144,000 plaintext bytes, 250 chunks, 262,148,000 encrypted chunk bytes. The test verified every saved plaintext byte. Publication took {bench['uploadMs']/1000:.1f} seconds and download/decryption took {bench['downloadMs']/1000:.1f} seconds on this machine using PGlite and headless Chromium."),
 para(f"A separate two-instance PostgreSQL rate-limit probe sent 200 requests at concurrency 20. Exactly 30 new sessions succeeded and 170 received 429. Observed p95 latency was {load['p95Ms']:.1f} ms. This is a budget-coordination probe, not a production capacity guarantee."),
 para('Evidence: benchmark-results/250-mib.json, postgres-load.json, restore.json and docs/evidence.json. Timings depend on this machine, storage and concurrent test activity. No real-phone or production traffic benchmark is claimed.'),
])
page('Deployment and remaining external actions',[
 para('The supplied Dockerfile runs as an unprivileged Node user. compose.yaml supplies PostgreSQL readiness, persistence and a loopback API port. Caddy configuration terminates HTTPS. Proxy hop trust is explicit. PostgreSQL coordinates rate budgets across API instances.'),
 para('Health and token-protected metrics report storage and cleanup backlog. Cleanup purges expired file rows, reclaims incomplete uploads after 24 hours and clears proximity fields after 24 hours. Backups and downloaded copies follow their own retention policies.'),
 para('Required institutional actions','Heading2'),
 para('1. Supply and review an independent external ceremony for this v2 circuit. Import verifies the ptau/zkey relationship and hashes, but cannot prove entropy destruction or replace independent participants.'),
 para('2. Supply an institution-held issuer key, authenticated roster/credential delivery channel, issuer rotation policy and a worker that applies scoped revocations across affected rooms. No real institution credentials or student records were invented.'),
 para('3. Select a production domain/host, configure secrets and HTTPS, run the supplied CI on the actual repository, set monitoring thresholds and exercise the institution\'s backup/restore policy.'),
 para('4. Run acceptance tests on actual phones and supported Safari versions, and commission independent cryptographic/application security review before relying on real student eligibility.'),
 para('The software and local evidence are available now. External deployment, institutional onboarding and an independent ceremony cannot be truthfully marked complete in this local session. Participant uploads remain excluded by request.'),
 para('Sources and reproduction','Heading2'),
 para('README.md, DEPLOYMENT.md, AUDIT.md, numbered SQL migrations, e2e/ and tests/, and the evidence JSON files. Ceremony procedure follows the primary snarkjs documentation: https://github.com/iden3/snarkjs#readme.'),
])
SimpleDocTemplate(str(report),pagesize=(612,792),rightMargin=42,leftMargin=42,topMargin=40,bottomMargin=45,title='Portkey - Current Implementation and Feature Mapping').build(story,onFirstPage=footer,onLaterPages=footer)
# Preserve the existing 14-slide PDF format and 16:9 canvas.
deck=OUT/'Portkey Presentation.pdf'; c=canvas.Canvas(str(deck),pagesize=(1440,810)); c.setTitle('Portkey - Encrypted Room File Sharing')
def slide(number,title,lines,photo=None):
 c.setFillColor(BG);c.rect(0,0,1440,810,fill=1,stroke=0)
 c.setFillColor(ACCENT);c.setFont('Noto',18);c.drawString(78,740,'PORTKEY  /  FULL STACK DEVELOPMENT')
 p=Paragraph(escape(title),ParagraphStyle('SlideTitle',fontName='Noto',fontSize=46,leading=54,textColor=INK));pw,ph=p.wrap(1250,200);p.drawOn(c,78,665-ph+48)
 y=530; width=790 if photo else 1240
 for line in lines:
  p=Paragraph(escape(line),ParagraphStyle('SlideBody',fontName='Noto',fontSize=26,leading=38,textColor=INK));w,h=p.wrap(width,450);p.drawOn(c,78,y-h);y-=h+26
 if photo and photo.exists():
  from PIL import Image as PILImage
  w,h=PILImage.open(photo).size
  if h/w > 2:
   c.saveState();clip=c.beginPath();clip.rect(880,160,480,330);c.clipPath(clip,stroke=0);c.drawImage(str(photo),880,490-h*480/w,width=480,height=h*480/w,mask='auto');c.restoreState()
  else:
   scale=min(480/w,445/h);c.drawImage(str(photo),880,160,width=w*scale,height=h*scale,preserveAspectRatio=True,mask='auto')
 c.setFillColor(MUTED);c.setFont('Noto',16);c.drawString(78,48,'1 NOVEMBER 2026  /  IMPLEMENTATION AND LOCAL TEST EVIDENCE');c.drawRightString(1360,48,f'{number:02d} / 14');c.showPage()
slides=[
 ('Encrypted room file sharing',['Temporary rooms, browser encryption and zero-knowledge credential admission.','Organizers distribute files. Participant uploads are excluded.'],ROOT/'public/photos/set-old-keys-hanging-wall.webp'),
 ('The room workflow',['Create a draft and choose its deadline. Add optional eligibility and location requirements.','Open the room, back up encryption and ownership recovery keys, then send a trusted invitation.','Approve participants or admit them through credential proofs.']),
 ('Application architecture',['React and TypeScript perform encryption and proof generation in the browser.','Express enforces lifecycle, access, proofs and quotas.','PostgreSQL or PGlite stores ciphertext, public keys and operational records.']),
 ('Privacy boundaries',['Private file content, names and decryption keys stay protected by browser cryptography.','Labels, room relationships, sizes, timing and reported location remain visible to the service.','A malicious application origin or compromised browser can steal secrets.']),
 ('Credential protocol v2',['The institution signs hidden credential possession plus department, year and expiry.','Groth16 proves eligibility and derives a room-specific nullifier.','A fresh browser-session challenge prevents copied proofs from taking another session’s seat.']),
 ('Credential lifecycle',['Successful admission consumes the ten-minute challenge. Expiry continues to govern file access.','Issuer-signed room revocations block future proofs and existing membership.','Institution-wide revocation needs the issuer’s worker to apply the scoped policy across affected rooms.']),
 ('Encrypted distribution',['AES-256-GCM encrypts one-MiB chunks and metadata using separate derived keys.','HPKE wraps the file key separately for each eligible recipient.','Immutable retries and the final SHA-256 manifest protect acceptance and authenticated downloads.']),
 ('Durable upload resume',['The browser keeps the source snapshot, plan and immutable encrypted chunks locally.','A reservation commits before encryption. Ciphertext commits before upload.','Interrupted reservations require a fresh key. A reload can safely resume saved ciphertext. Changed recipient keys require a new plan.']),
 ('Late arrivals and rotation',['The organizer grants earlier files by adding recipient envelopes over existing ciphertext.','Key rotation atomically rewraps every existing file key and rejects incomplete replacement sets.','New organizer fingerprints require a fresh trusted invitation and backup.']),
 ('Ownership recovery',['A separate one-time recovery code moves management access into a new browser.','An encrypted key backup restores decryption after recovery.','Previously downloaded files cannot be recalled.'],ROOT.parent/'outputs/Portkey_Recovery_Desktop.png'),
 ('Production operations',['PostgreSQL shares rate budgets across API instances.','Docker, HTTPS proxy configuration, protected metrics, cleanup and backup scripts are supplied.','Independent ceremony artifacts and an institution-held issuer remain production prerequisites.']),
 ('Automated evidence',[f"{evidence['apiTests']} API tests pass on PGlite and {evidence['postgresTests']} on PostgreSQL 17.",evidence['compatibilitySummary'],'Browser evidence covers key recovery, rotation, earlier-file grants, reload/resume and production HTTPS proofs.']),
 ('250 MiB transfer results',[f"250 chunks preserved all 262,144,000 plaintext bytes.",f"Publication: {bench['uploadMs']/1000:.1f} s. Download and decryption: {bench['downloadMs']/1000:.1f} s.",'Measured locally with PGlite and headless Chromium. This is not a production throughput guarantee.']),
 ('Institutional handoff',['Supply independent ceremony participation, issuer custody, roster integration and private credential delivery.','Choose the domain and hosting, run CI, and set monitoring and backup policies.','Complete real-device acceptance and independent security review before institutional use.'])
]
for index,content in enumerate(slides,1):slide(index,*content)
c.save()
parent=ROOT.parent/'docs';parent.mkdir(exist_ok=True)
for path in [report,deck]: shutil.copy2(path,parent/path.name)
print(report);print(deck)
