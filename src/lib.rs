//! greybags — Windows ShellBags dissector and analysis library.
//!
//! * [`regf`] — offline registry hive parser with transaction log replay
//!   and deleted-record carving.
//! * [`shellitem`] — field-level shell item (ITEMIDLIST) dissector.
//! * [`shellbags`] — BagMRU/Bags traversal and deleted-entry recovery.
//! * [`analysis`] — timeline, triage findings and summary statistics.
//! * [`output`] — CSV/JSON/bodyfile writers.
//! * [`ezt`] — Eric Zimmerman SBECmd integration (run + compare).

pub mod analysis;
pub mod demo;
pub mod ezt;
pub mod output;
pub mod regf;
pub mod shellbags;
pub mod shellitem;
pub mod util;
