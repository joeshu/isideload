use crate::{
    dev::{
        app_groups::AppGroupsApi,
        app_ids::{AppId, AppIdsApi, Profile},
        developer_session::DeveloperSession,
        devices::DevicesApi,
        teams::{DeveloperTeam, TeamsApi},
    },
    sideload::{
        TeamSelection,
        application::{Application, SpecialApp},
        builder::MaxCertsBehavior,
        cert_identity::CertificateIdentity,
        sign,
    },
    util::{device::IdeviceInfo, storage::SideloadingStorage},
};

use std::path::PathBuf;

use apple_codesign::ProvisioningProfile;
use idevice::provider::IdeviceProvider;
use plist::Dictionary;
use rootcause::{option_ext::OptionExt, prelude::*};
use tracing::info;

pub struct ExportedSigningIdentity {
    pub p12: Vec<u8>,
    pub p12_password: String,
    pub team_id: String,
    pub certificate_serial_number: String,
    pub machine_id: String,
    pub machine_name: String,
}

pub struct ExportedProvisioningProfile {
    pub mobileprovision: Vec<u8>,
    pub filename: String,
    pub uuid: String,
    pub name: String,
    pub app_identifier: String,
    pub expiration_date: String,
    pub is_free_provisioning_profile: Option<bool>,
}

pub struct Sideloader {
    team_selection: TeamSelection,
    storage: Box<dyn SideloadingStorage>,
    dev_session: DeveloperSession,
    machine_name: String,
    apple_email: String,
    max_certs_behavior: MaxCertsBehavior,
    //extensions_behavior: ExtensionsBehavior,
    delete_app_after_install: bool,
    team: Option<DeveloperTeam>,
}

impl Sideloader {
    /// Construct a new `Sideloader` instance with the provided configuration
    ///
    /// See [`crate::sideload::SideloaderBuilder`] for more details and a more convenient way to construct a `Sideloader`.
    pub fn new(
        dev_session: DeveloperSession,
        apple_email: String,
        team_selection: TeamSelection,
        max_certs_behavior: MaxCertsBehavior,
        machine_name: String,
        storage: Box<dyn SideloadingStorage>,
        //extensions_behavior: ExtensionsBehavior,
        delete_app_after_install: bool,
    ) -> Self {
        Sideloader {
            team_selection,
            storage,
            dev_session,
            machine_name,
            apple_email,
            max_certs_behavior,
            //extensions_behavior,
            delete_app_after_install,
            team: None,
        }
    }

    pub async fn export_signing_identity(
        &mut self,
        password: Option<&str>,
    ) -> Result<ExportedSigningIdentity, Report> {
        let team = self.get_team().await?;
        let cert_identity = CertificateIdentity::retrieve(
            &self.machine_name,
            &self.apple_email,
            &mut self.dev_session,
            &team,
            self.storage.as_ref(),
            &self.max_certs_behavior,
        )
        .await
        .context("Failed to retrieve certificate identity for export")?;

        let p12_password = password
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| cert_identity.machine_id.clone());
        let p12 = cert_identity
            .as_p12(&p12_password)
            .await
            .context("Failed to export certificate identity as PKCS#12")?;

        Ok(ExportedSigningIdentity {
            p12,
            p12_password,
            team_id: team.team_id,
            certificate_serial_number: cert_identity.get_serial_number(),
            machine_id: cert_identity.machine_id,
            machine_name: cert_identity.machine_name,
        })
    }

    pub async fn export_provisioning_profile(
        &mut self,
        app_id_id: &str,
    ) -> Result<ExportedProvisioningProfile, Report> {
        let team = self.get_team().await?;
        let response = self.dev_session.list_app_ids(&team, None).await?;
        let app_id: AppId = response
            .app_ids
            .into_iter()
            .find(|app| app.app_id_id == app_id_id)
            .ok_or_else(|| report!("App ID not found: {}", app_id_id))?;

        let profile = self
            .dev_session
            .download_team_provisioning_profile(&team, &app_id, None)
            .await
            .context("Failed to download provisioning profile for export")?;

        Ok(ExportedProvisioningProfile {
            mobileprovision: profile.encoded_profile.as_ref().to_vec(),
            filename: profile.filename,
            uuid: profile.uuid,
            name: profile.name,
            app_identifier: app_id.identifier,
            expiration_date: format!("{:?}", profile.date_expire),
            is_free_provisioning_profile: profile.is_free_provisioning_profile,
        })
    }

    /// Sign the app at the provided path and return the path to the signed app bundle (in a temp dir). To sign and install, see [`Self::install_app`].
    pub async fn sign_app<F, Fut>(
        &mut self,
        app_path: PathBuf,
        team: Option<DeveloperTeam>,
        // this will be replaced with proper entitlement handling later
        increased_memory_limit: bool,
        progress_callback: Option<F>,
    ) -> Result<(PathBuf, Option<SpecialApp>), Report>
    where
        F: Fn(f32) -> Fut,
        Fut: Future<Output = ()>,
    {
        let team = match team {
            Some(t) => t,
            None => self.get_team().await?,
        };
        let cert_identity = CertificateIdentity::retrieve(
            &self.machine_name,
            &self.apple_email,
            &mut self.dev_session,
            &team,
            self.storage.as_ref(),
            &self.max_certs_behavior,
        )
        .await
        .context("Failed to retrieve certificate identity")?;

        if let Some(callback) = &progress_callback {
            callback(0.1).await;
        }

        let mut app = Application::new(app_path)?;
        let special = app.get_special_app();

        let main_bundle_id = app.main_bundle_id()?;
        let main_app_name = app.main_app_name()?;
        let main_app_id_str = format!("{}.{}", main_bundle_id, team.team_id);
        app.update_bundle_id(&main_bundle_id, &main_app_id_str)?;
        let mut app_ids = app
            .register_app_ids(
                /*&self.extensions_behavior, */ &mut self.dev_session,
                &team,
            )
            .await?;
        let main_app_id = match app_ids
            .iter()
            .find(|app_id| app_id.identifier == main_app_id_str)
        {
            Some(id) => id,
            None => {
                bail!(
                    "Main app ID {} not found in registered app IDs",
                    main_app_id_str
                );
            }
        }
        .clone();

        let group_identifier = format!(
            "group.{}",
            if Some(SpecialApp::SideStoreLc) == special {
                format!("com.SideStore.SideStore.{}", team.team_id)
            } else {
                main_app_id_str.clone()
            }
        );

        let app_group = self
            .dev_session
            .ensure_app_group(&team, &main_app_name, &group_identifier, None)
            .await?;

        for app_id in app_ids.iter_mut() {
            app_id
                .ensure_group_feature(&mut self.dev_session, &team)
                .await?;

            self.dev_session
                .assign_app_group(&team, &app_group, app_id, None)
                .await?;

            if increased_memory_limit {
                self.dev_session
                    .add_increased_memory_limit(&team, app_id)
                    .await?;
            }
        }

        if let Some(callback) = &progress_callback {
            callback(0.15).await;
        }

        info!("App IDs configured");

        app.apply_special_app_behavior(&special, &group_identifier, &cert_identity)
            .await
            .context("Failed to modify app bundle")?;

        let main_provisioning_profile = self
            .dev_session
            .download_team_provisioning_profile(&team, &main_app_id, None)
            .await?;

        let mut provisioning_profiles: Vec<(String, Profile, Dictionary)> = Vec::new();

        for id in app_ids
            .into_iter()
            .filter(|id| id.identifier != main_app_id.identifier)
        {
            let bundle_id = id.identifier.clone();

            let profile = self
                .dev_session
                .download_team_provisioning_profile(&team, &id, None)
                .await
                .context(format!(
                    "Failed to download provisioning profile for {}",
                    bundle_id
                ))?;

            let parsed_profile = ProvisioningProfile::parse(profile.encoded_profile.as_ref())?;
            let entitlements = parsed_profile.entitlements().clone();

            provisioning_profiles.push((bundle_id, profile, entitlements));
        }

        if let Some(callback) = &progress_callback {
            callback(0.2).await;
        }

        info!("Acquired provisioning profile");

        app.bundle.write_info()?;
        for ext in app.bundle.app_extensions_mut() {
            ext.write_info()?;
        }
        for ext in app.bundle.frameworks_mut() {
            ext.write_info()?;
        }

        // isideload_vfs::fs::write(
        //     app.bundle.bundle_dir.join("embedded.mobileprovision"),
        //     provisioning_profile.encoded_profile.as_ref(),
        // )?;

        if let Some(callback) = &progress_callback {
            callback(0.3).await;
        }

        sign::sign(
            &mut app,
            &cert_identity,
            &main_provisioning_profile,
            &provisioning_profiles,
            &special,
            &team,
            progress_callback,
        )
        .await
        .context("Failed to sign app")?;

        info!("App signed!");

        Ok((app.bundle.bundle_dir.clone(), special))
    }

    #[cfg(feature = "install")]
    /// Sign and install an app to a device.
    pub async fn install_app<F, Fut>(
        &mut self,
        device_provider: &impl IdeviceProvider,
        app_path: PathBuf,
        // this is gross but will be replaced with proper entitlement handling later
        increased_memory_limit: bool,
        progress_callback: Option<F>,
    ) -> Result<Option<SpecialApp>, Report>
    where
        F: Fn(f32) -> Fut,
        Fut: Future<Output = ()>,
    {
        let device_info = IdeviceInfo::from_device(device_provider).await?;

        let team = self.get_team().await?;
        self.dev_session
            .ensure_device_registered(&team, &device_info.name, &device_info.udid, None)
            .await?;

        let (signed_app_path, special_app) = self
            .sign_app(
                app_path,
                Some(team),
                increased_memory_limit,
                progress_callback,
            )
            .await?;

        info!("Transferring App...");

        crate::sideload::install::install_app(device_provider, &signed_app_path, |progress| {
            info!("Installing: {}%", progress);
        })
        .await
        .context("Failed to install app on device")?;

        if self.delete_app_after_install
            && let Err(e) = isideload_vfs::fs::remove_dir_all(signed_app_path)
        {
            tracing::warn!("Failed to remove temporary signed app file: {}", e);
        }

        Ok(special_app)
    }

    /// Get the developer team according to the configured team selection behavior
    pub async fn get_team(&mut self) -> Result<DeveloperTeam, Report> {
        if let Some(team) = &self.team {
            return Ok(team.clone());
        }
        let teams = self.dev_session.list_teams().await?;
        let team = match teams.len() {
            0 => {
                bail!("No developer teams available")
            }
            1 => teams.into_iter().next().ok_or_report()?,
            _ => {
                info!(
                    "Multiple developer teams found, {} as per configuration",
                    self.team_selection
                );
                match &self.team_selection {
                    TeamSelection::First => teams.into_iter().next().ok_or_report()?,
                    TeamSelection::PromptOnce(prompt_fn)
                    | TeamSelection::PromptAlways(prompt_fn) => {
                        let selection =
                            prompt_fn(&teams).ok_or_else(|| report!("No team selected"))?;
                        teams
                            .into_iter()
                            .find(|t| t.team_id == selection)
                            .ok_or_else(|| report!("No team found with ID {}", selection))?
                    }
                }
            }
        };
        if !matches!(&self.team_selection, TeamSelection::PromptAlways(_)) {
            self.team = Some(team.clone());
        }
        Ok(team)
    }

    pub fn get_dev_session(&mut self) -> &mut DeveloperSession {
        &mut self.dev_session
    }

    pub fn get_email(&self) -> &str {
        &self.apple_email
    }
}
