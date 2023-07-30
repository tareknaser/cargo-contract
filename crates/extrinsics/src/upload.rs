// Copyright 2018-2023 Parity Technologies (UK) Ltd.
// This file is part of cargo-contract.
//
// cargo-contract is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// cargo-contract is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with cargo-contract.  If not, see <http://www.gnu.org/licenses/>.

use super::{
    display_dry_run_result_warning,
    events::DisplayEvents,
    name_value_println,
    runtime_api::api::{
        self,
        contracts::events::CodeStored,
        runtime_types::pallet_contracts::wasm::Determinism,
    },
    state,
    state_call,
    submit_extrinsic,
    Balance,
    Client,
    CodeHash,
    DefaultConfig,
    ErrorVariant,
    ExtrinsicOpts,
    Missing,
    PairSigner,
    TokenMetadata,
    WasmCode,
};
use anyhow::Result;
use core::marker::PhantomData;
use pallet_contracts_primitives::CodeUploadResult;
use scale::Encode;
use std::fmt::Debug;
use subxt::{
    Config,
    OnlineClient,
};
use tokio::runtime::Runtime;

#[derive(Debug, clap::Args)]
#[clap(name = "upload", about = "Upload a contract's code")]
pub struct UploadCommand {
    #[clap(flatten)]
    extrinsic_opts: ExtrinsicOpts,
    /// Export the call output in JSON format.
    #[clap(long, conflicts_with = "verbose")]
    output_json: bool,
}

/// A builder for the upload command.
pub struct UploadCommandBuilder<ExtrinsicOptions> {
    opts: UploadCommand,
    marker: PhantomData<fn() -> ExtrinsicOptions>,
}

impl UploadCommandBuilder<Missing<state::ExtrinsicOptions>> {
    /// Sets the extrinsic operation.
    pub fn extrinsic_opts(
        self,
        extrinsic_opts: ExtrinsicOpts,
    ) -> UploadCommandBuilder<state::ExtrinsicOptions> {
        UploadCommandBuilder {
            opts: UploadCommand {
                extrinsic_opts,
                ..self.opts
            },
            marker: PhantomData,
        }
    }
}

impl<E> UploadCommandBuilder<E> {
    /// Sets whether to export the call output in JSON format.
    pub fn output_json(self, output_json: bool) -> Self {
        let mut this = self;
        this.opts.output_json = output_json;
        this
    }
}

impl UploadCommandBuilder<state::ExtrinsicOptions> {
    /// Finishes construction of the upload command.
    pub async fn done(self) -> UploadExec {
        let upload_command = self.opts;
        upload_command.preprocess().await.unwrap()
    }
}

#[allow(clippy::new_ret_no_self)]
impl UploadCommand {
    /// Creates a new `UploadCommand` instance.
    pub fn new() -> UploadCommandBuilder<Missing<state::ExtrinsicOptions>> {
        UploadCommandBuilder {
            opts: Self {
                extrinsic_opts: ExtrinsicOpts::default(),
                output_json: false,
            },
            marker: PhantomData,
        }
    }

    pub fn is_json(&self) -> bool {
        self.output_json
    }

    /// Helper method for preprocessing contract artifacts.
    pub async fn preprocess(&self) -> Result<UploadExec> {
        let artifacts = self.extrinsic_opts.contract_artifacts()?;
        let signer = super::pair_signer(self.extrinsic_opts.signer()?);

        let artifacts_path = artifacts.artifact_path().to_path_buf();
        let code = artifacts.code.ok_or_else(|| {
            anyhow::anyhow!(
                "Contract code not found from artifact file {}",
                artifacts_path.display()
            )
        })?;
        let url = self.extrinsic_opts.url_to_string();
        let client = OnlineClient::from_url(url.clone()).await?;
        Ok(UploadExec {
            opts: self.extrinsic_opts.clone(),
            output_json: self.output_json,
            client,
            code,
            signer,
        })
    }

    pub fn run(&self) -> Result<(), ErrorVariant> {
        Runtime::new()?
            .block_on(async {
                let upload_exec = self.preprocess().await?;
                let code_hash = upload_exec.code.code_hash();

                if !upload_exec.opts.execute {
                    match upload_exec.upload_code_rpc().await? {
                        Ok(result) => {
                            let upload_result = UploadDryRunResult {
                                result: String::from("Success!"),
                                code_hash: format!("{:?}", result.code_hash),
                                deposit: result.deposit,
                            };
                            if upload_exec.output_json {
                                println!("{}", upload_result.to_json()?);
                            } else {
                                upload_result.print();
                                display_dry_run_result_warning("upload");
                            }
                        }
                        Err(err) => {
                            let metadata = upload_exec.client.metadata();
                            let err = ErrorVariant::from_dispatch_error(&err, &metadata)?;
                            if upload_exec.output_json {
                                return Err(err)
                            } else {
                                name_value_println!("Result", err);
                            }
                        }
                    }
                } else {
                    let upload_result = upload_exec.upload_code().await?;
                    let display_events = upload_result.display_events;
                    let output = if upload_exec.output_json {
                        display_events.to_json()?
                    } else {
                        let token_metadata = TokenMetadata::query(&upload_exec.client).await?;
                        display_events.display_events(upload_exec.opts.verbosity()?, &token_metadata)?
                    };
                    println!("{output}");
                    if let Some(code_stored) =
                        upload_result.code_stored
                    {
                        let upload_result = CodeHashResult {
                            code_hash: format!("{:?}", code_stored.code_hash),
                        };
                        if upload_exec.output_json {
                            println!("{}", upload_result.to_json()?);
                        } else {
                            upload_result.print();
                        }
                    } else {
                        let code_hash = hex::encode(code_hash);
                        return Err(anyhow::anyhow!(
                            "This contract has already been uploaded with code hash: 0x{code_hash}"
                        )
                        .into())
                    }
                }
                Ok(())
        })
    }
}

pub struct UploadExec {
    opts: ExtrinsicOpts,
    output_json: bool,
    client: Client,
    code: WasmCode,
    signer: PairSigner,
}

impl UploadExec {
    async fn upload_code_rpc(&self) -> Result<CodeUploadResult<CodeHash, Balance>> {
        let url = self.opts.url_to_string();
        let token_metadata = TokenMetadata::query(&self.client).await?;
        let storage_deposit_limit = self
            .opts
            .storage_deposit_limit
            .as_ref()
            .map(|bv| bv.denominate_balance(&token_metadata))
            .transpose()?;
        let call_request = CodeUploadRequest {
            origin: self.signer.account_id().clone(),
            code: self.code.0.clone(),
            storage_deposit_limit,
            determinism: Determinism::Enforced,
        };
        state_call(&url, "ContractsApi_upload_code", call_request).await
    }

    pub async fn upload_code(&self) -> Result<UploadResult, ErrorVariant> {
        let token_metadata = TokenMetadata::query(&self.client).await?;
        let storage_deposit_limit = self.opts.storage_deposit_limit(&token_metadata)?;
        let call = crate::runtime_api::api::tx().contracts().upload_code(
            self.code.0.clone(),
            storage_deposit_limit,
            Determinism::Enforced,
        );

        let result = submit_extrinsic(&self.client, &call, &self.signer).await?;
        let display_events =
            DisplayEvents::from_events(&result, None, &self.client.metadata())?;

        let code_stored = result.find_first::<api::contracts::events::CodeStored>()?;
        Ok(UploadResult {
            code_stored,
            display_events,
        })
    }
}

/// A struct that encodes RPC parameters required for a call to upload a new code.
#[derive(Encode)]
pub struct CodeUploadRequest {
    origin: <DefaultConfig as Config>::AccountId,
    code: Vec<u8>,
    storage_deposit_limit: Option<Balance>,
    determinism: Determinism,
}

#[derive(serde::Serialize)]
pub struct CodeHashResult {
    code_hash: String,
}

pub struct UploadResult {
    code_stored: Option<CodeStored>,
    display_events: DisplayEvents,
}

#[derive(serde::Serialize)]
pub struct UploadDryRunResult {
    result: String,
    code_hash: String,
    deposit: Balance,
}

impl CodeHashResult {
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn print(&self) {
        name_value_println!("Code hash", format!("{:?}", self.code_hash));
    }
}

impl UploadDryRunResult {
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn print(&self) {
        name_value_println!("Result", self.result);
        name_value_println!("Code hash", format!("{:?}", self.code_hash));
        name_value_println!("Deposit", format!("{:?}", self.deposit));
    }
}
