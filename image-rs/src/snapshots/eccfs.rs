use std::fs;
use std::path::{Path, PathBuf};

use log::info;
use anyhow::{anyhow, Result};
use nix::mount::MsFlags;
use fs_extra::dir;

use ocicrypt_rs::blockcipher::rand::rand_bytes;

use crate::snapshots::{MountPoint, Snapshotter};

const LD_LIB: &str = "ld-linux-x86-64.so.2";

#[derive(Debug)]
pub struct EccOvlFs {
    pub data_dir: PathBuf,
}

fn clear_path(mount_path: &Path) -> Result<()> {
    let mut from_paths = Vec::new();
    let paths = fs::read_dir(
        mount_path
            .to_str()
            .ok_or(anyhow!("mount_path does not exist"))?,
    )?;
    for path in paths {
        from_paths.push(path?.path());
    }
    fs_extra::remove_items(&from_paths)?;

    Ok(())
}

fn create_dir(create_path: &Path) -> Result<()> {
    if !create_path.exists() {
        fs::create_dir_all(create_path)?;
    }

    Ok(())
}

// returns randomly generted random 128 bit key
fn generate_random_key() -> [u8; 16] {
    let mut key: [u8; 16] = [0u8; 16];

    rand_bytes(&mut key).expect("Random fill failed");

    key
}

fn create_environment(mount_path: &Path) -> Result<()> {
    let mut from_paths = Vec::new();
    let mut copy_options = dir::CopyOptions::new();
    copy_options.overwrite = true;

    // copy the libs required by occlum to the mount path
    let path_lib64 = mount_path.join("lib64");
    create_dir(&path_lib64)?;

    let lib64_libs = [LD_LIB];
    let ori_path_lib64 = Path::new("/lib64");
    for lib in lib64_libs.iter() {
        from_paths.push(ori_path_lib64.join(lib));
    }

    // if ld-linux-x86-64.so.2 as symlink exist in ${path_lib64},
    // copy ld-linux-x86-64.so.2 from occlum to ${path_lib64} failed (file exists).
    // so firstly remove it.
    let ld_lib = path_lib64.join(LD_LIB);
    if fs::symlink_metadata(ld_lib.as_path()).is_ok() {
        fs::remove_file(ld_lib)?;
    }
    fs_extra::copy_items(&from_paths, &path_lib64, &copy_options)?;
    from_paths.clear();

    let path_opt = mount_path
        .join("opt")
        .join("occlum")
        .join("glibc")
        .join("lib");
    fs::create_dir_all(&path_opt)?;

    let occlum_lib = [
        "libc.so.6",
        "libdl.so.2",
        "libm.so.6",
        "libpthread.so.0",
        "libresolv.so.2",
        "librt.so.1",
    ];

    let ori_occlum_lib_path = Path::new("/")
        .join("opt")
        .join("occlum")
        .join("glibc")
        .join("lib");
    for lib in occlum_lib.iter() {
        from_paths.push(ori_occlum_lib_path.join(lib));
    }
    fs_extra::copy_items(&from_paths, &path_opt, &copy_options)?;
    from_paths.clear();

    let sys_path = ["dev", "etc", "host", "lib", "proc", "root", "sys", "tmp"];
    for path in sys_path.iter() {
        create_dir(&mount_path.join(path))?;
    }

    Ok(())
}

const ECCFS_RW_IMAGE_NAME: &str = "run.rwimage";

impl Snapshotter for EccOvlFs {
    fn mount(&mut self, layer_path: &[&str], mount_path: &Path) -> Result<MountPoint> {
        let flags = MsFlags::empty();

        if !mount_path.exists() {
            fs::create_dir_all(mount_path)?;
        }

        // store the rootfs in different places according to the cid
        let cid = mount_path
            .parent()
            .ok_or(anyhow!("parent do not exist"))?
            .file_name()
            .ok_or(anyhow!("Unknown error: file name parse fail"))?;

        let eccfs_dir_host = Path::new("/images").join(cid).join("eccfs");
        let eccfs_work_dir = Path::new("/eccfs_tmp");
        if !eccfs_work_dir.exists() {
            fs::create_dir_all(eccfs_work_dir)?;
        } else {
            clear_path(&eccfs_work_dir)?;
        }

        nix::mount::mount(
            Some("hostfs"),
            mount_path,
            Some("hostfs"),
            flags,
            Some(format!("dir={}", eccfs_dir_host.display()).as_str()),
        ).map_err(|e| {
            anyhow!(
                "failed to mount {:?} to {:?}, with error: {}",
                "hostfs",
                mount_path,
                e
            )
        })?;

        // clear the mount_path if there is something
        clear_path(mount_path)?;

        let mut fsmodes = Vec::new();

        // build empty rw layer
        let rw_mode = eccfs_builder::rw::create_empty(
            &mount_path.join(ECCFS_RW_IMAGE_NAME),
            Some(generate_random_key()),
        )?;
        fsmodes.push(rw_mode);

        // occlum env is the first RO layer
        let occlum_env = eccfs_work_dir.join("occlum_env");
        fs::create_dir_all(&occlum_env)?;
        create_environment(&occlum_env)?;
        let fsmode = eccfs_builder::ro::build_from_dir(
            &occlum_env,
            &mount_path,
            Path::new(format!("{:04}.roimage", 0).as_str()),
            eccfs_work_dir,
            Some(generate_random_key()),
        )?;
        fsmodes.push(fsmode);
        clear_path(eccfs_work_dir)?;

        // container image layers
        for (i, p) in layer_path.iter().enumerate() {
            let fsmode = eccfs_builder::ro::build_from_dir(
                Path::new(p),
                &mount_path,
                Path::new(format!("{:04}.roimage", i+1).as_str()),
                eccfs_work_dir,
                Some(generate_random_key()),
            )?;
            fsmodes.push(fsmode);
            clear_path(eccfs_work_dir)?;
        }

        nix::mount::umount(mount_path)?;

        let key_mount_options = format!(
            "dir={}",
            Path::new("/images")
                .join(cid)
                .join("keys/sefs/lower")
                .display()
        );

        let keys_mount_path = Path::new("/keys");
        nix::mount::mount(
            Some("sefs"),
            keys_mount_path,
            Some("sefs"),
            flags,
            Some(key_mount_options.as_str()),
        ).map_err(|e| {
            anyhow!(
                "failed to mount {:?} to {:?}, with error: {}",
                "sefs",
                keys_mount_path,
                e
            )
        })?;

        let mode_str = fsmodes.into_iter().map(
            |m| {
                let s = if m.is_encrypted() {
                    "enc"
                } else {
                    "int"
                };
                format!("{}-{}", s, hex::encode_upper(m.into_key_entry()))
            }
        ).collect::<Vec<_>>().join(":");

        std::fs::write(&keys_mount_path.join("key.txt"), &mode_str)?;
        nix::mount::umount(keys_mount_path)?;

        Ok(MountPoint {
            r#type: "eccfs".into(),
            mount_path: mount_path.to_path_buf(),
            work_dir: self.data_dir.to_path_buf(),
        })
    }

    fn unmount(&self, mount_point: &MountPoint) -> Result<()> {
        nix::mount::umount(mount_point.mount_path.as_path())?;

        Ok(())
    }
}
