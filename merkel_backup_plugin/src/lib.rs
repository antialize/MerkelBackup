//! Defines an interface to add plugins to MerkelBackup
#![allow(non_camel_case_types)]
#![allow(non_local_definitions)]

use abi_stable::{
    RMut, StableAbi,
    library::{LibraryError, RootModule},
    package_version_strings, sabi_trait,
    sabi_types::VersionStrings,
    std_types::{RBox, RBoxError, RCowStr, ROption, RResult, RStr, RString, RVec},
};

/// The type of error used by plugins
pub type Error = RBoxError;
/// The type of results used by plugins
pub type Result<T, E = Error> = RResult<T, E>;

/// Result of [BackupContext::get_chunks]
#[repr(C)]
#[derive(StableAbi)]
pub struct Chunks {
    /// Comma separated chunk hashes
    pub chunks: RString,
    /// The combined size of all the chunks
    pub size: i64,
}

/// Callback context given to [Plugin::scan] and [Plugin::backup]
#[sabi_trait]
pub trait BackupContext {
    /// Get the chunk size that should be used when backing up
    fn chunk_size(&self) -> usize;

    /// Look in the cache for the current set of chunks for the given path with the given size and mtime
    ///
    /// If the size is not given check for any size, and return the size
    fn get_chunks(&mut self, path: RStr, size: ROption<i64>, mtime: i64)
    -> Result<ROption<Chunks>>;

    /// Update the chunks in the cache for the given path, with the given size and mtime
    fn update_chunks(&mut self, path: RStr, size: i64, mtime: i64, chunks: RStr) -> Result<()>;

    /// Check if the remote server has the given set of comma separated chunk hashes
    fn has_chunks(&mut self, chunks: RStr) -> Result<bool>;

    /// Upload the chunk to the remote server returning its hash
    fn push_chunk(&mut self, content: abi_stable::std_types::RSlice<u8>) -> Result<RString>;

    /// Add entry line to the backup root
    fn add_entry(&mut self, line: RStr) -> Result<()>;

    /// Register to scan that we will backup this many files using this many bytes.
    /// Used for progress tracking
    fn scan_register(&mut self, files: usize, bytes: usize);
}

/// Reference to a [BackupContext] implementation
pub type BackupContextRef<'a> = BackupContext_TO<'a, RMut<'a, ()>>;

/// Callback context given to [Plugin::validate_ent] and [Plugin::recover_ent]
#[sabi_trait]
pub trait ReadContext {
    /// Read the content of a chunk into output
    fn get_chunk(&mut self, chunk: RStr, output: &mut RVec<u8>) -> Result<()>;
    /// Check if the remote server has the given set of comma separated chunk hashes
    fn has_chunks(&mut self, chunks: RStr) -> Result<bool>;
}

/// Reference to a [ReadContext] implementation
pub type ReadContextRef<'a> = ReadContext_TO<'a, RMut<'a, ()>>;

/// Parsed content of an ent line
#[repr(C)]
#[derive(StableAbi)]
pub struct ParsedEnt<'a> {
    /// The type of object stored (this is plugin dependent)
    pub etype: RStr<'a>,
    /// The name of the object stored
    pub name: RCowStr<'a>,
    /// The chunks of the entry
    pub chunks: RStr<'a>,
    /// The size of all the chunks combined
    pub size: i64,
}
/// Base trait implemented by plugins
#[sabi_trait]
pub trait Plugin {
    /// Get the type name of the plugin (static for a given plugin)
    fn plugin(&self) -> RCowStr<'static>;

    /// Get the name of the plugin instance (can depend of the config)
    fn name(&self) -> RCowStr<'static>;

    /// Scan the host to look for unbacked entries, this is
    /// used for progress tracking
    fn scan(&mut self, context: BackupContextRef) -> Result<()>;

    /// Scan the host adding all files to the backup
    fn backup(&mut self, context: BackupContextRef) -> Result<()>;

    /// Parse an ent line emitted by this plugin
    fn parse_ent<'a>(&mut self, ent_line: RStr<'a>) -> Result<ParsedEnt<'a>>;

    /// Validate that the data for the given ent line is actually on the remote server
    fn validate_ent(&mut self, ent_line: RStr, full: bool, context: ReadContextRef) -> Result<()>;

    /// Check if an ent line matches the pattern used for backup recovery
    fn ent_matches_pattern(&mut self, ent_line: RStr, pattern: RStr) -> Result<bool>;

    /// Recover an entry from the backup
    fn recover_ent(
        &mut self,
        ent_line: RStr,
        dest: RStr,
        dry: bool,
        preserve_owner: bool,
        context: ReadContextRef,
    ) -> Result<()>;
}

/// Owned Box of [Plugin]
pub type PluginBox = Plugin_TO<'static, RBox<()>>;

#[repr(C)]
#[derive(StableAbi)]
#[sabi(kind(Prefix(prefix_ref = PluginLib_Ref)))]
#[sabi(missing_field(panic))]
pub struct PluginLib {
    pub new_plugin: extern "C" fn(config: RStr) -> Result<PluginBox>,
}

impl RootModule for PluginLib_Ref {
    abi_stable::declare_root_module_statics! {PluginLib_Ref}

    const BASE_NAME: &'static str = "merkel_backup_plugin";
    const NAME: &'static str = "merkel_backup_plugin";
    const VERSION_STRINGS: VersionStrings = package_version_strings!();
}

/// Load a plugin from the given directory
pub fn load_plugin(
    directory: &std::path::Path,
) -> std::result::Result<PluginLib_Ref, LibraryError> {
    PluginLib_Ref::load_from_file(directory)
}
