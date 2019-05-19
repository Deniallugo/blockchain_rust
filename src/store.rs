use std::path::Path;
use std::sync::{Arc, RwLock, RwLockReadGuard};
use std::fs;
use rkv::{Manager, SingleStore, StoreOptions, Rkv};

#[derive(Clone)]
pub(crate) struct Store {
    created_arc: Arc<RwLock<Rkv>>,
    name: String,
}

impl Store {
    pub(crate) fn new(path_str: &String, name: String) -> Self {
        let path = Path::new(path_str);
        fs::create_dir_all(path).unwrap();

        Self {
            name,
            created_arc: Manager::singleton().write().unwrap().get_or_create(path, Rkv::new).unwrap(),
        }
    }

    pub(crate) fn rkv(&self) -> RwLockReadGuard<Rkv> {
        self.created_arc.read().unwrap()
    }

    pub(crate) fn single_store(&self) -> SingleStore {
        let rkv = self.rkv();
        rkv.open_single("test", StoreOptions::create()).unwrap()
    }
}

