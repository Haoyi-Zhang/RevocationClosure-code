# Literature provenance and claim use

The bibliography contains 69 distinct records used across the main article (62) and separate supplement (seven additional records). Citation closure, duplicate detection, and parsed metadata are different from online source verification. Successful BibTeX compilation does not establish that every citation semantically supports every nearby sentence.

The closest-work comparison is intentionally adverse to overclaiming. Offline Delegation establishes infrastructure-independent delegation as prior art. Chubby establishes an acknowledgement-or-expiry recovery boundary. Maat combines delegation and short-lived capability revocation. The Transform architecture establishes distributed capability revocation. WAVE addresses decentralized transitive authorization. EVOKE and Pasture address offline revocation under different dissemination and trusted-hardware assumptions. Vouchsafe is identified as an arXiv preprint on offline capability graphs rather than peer-reviewed deployment evidence.

For this journal release, official publisher, society, archive, or author records and the relevant abstracts or passages were rechecked for the closest cited systems; the row-level status is recorded in `reference_audit.csv`. The Leases record uses the SOSP 1989 publication, pages 202--210, DOI 10.1145/74850.74870. A contact-network paper not used by a bundled experiment was removed rather than retained to increase the count. Historical reading-depth notes are not presented as fresh full-text review.

The evidence join is elementary. The paper's potentially publishable contribution is the precisely scoped observation-relative characterization, its durable reply and recovery obligations, and falsifiable executable correspondence. Importance relative to prior work remains a scientific and editorial judgment, not a template or citation-count property.

Primary comparison passages: [Chubby, Sections 2.7 and 4.4](https://www.usenix.org/legacy/event/osdi06/tech/full_papers/burrows/burrows.pdf)
describe acknowledgement-or-expiry cache invalidation and a worst-case lease
wait after uncertain recovery. [Maat, Sections 3.1, 3.4--3.5](https://escholarship.org/content/qt7h24p98z/qt7h24p98z_noSplash_e5100ba830219ea9d89456214b951b33.pdf)
cover synchronized-clock assumptions, automatic expiry, explicit early
revocation, and renewable delegated computation keys. Neither is treated as
a stateless latest-poll implementation. The local durable reference receives
the same observations as the journal and has identical closure semantics.

No external paper PDF, prior implementation, contact dataset, or third-party runtime is redistributed. Conference names and society URLs retained in the bibliography or audit tables identify legitimate scholarly sources; they are not publication-template dependencies.
