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
    events::DisplayEvents,
    name_value_println,
    parse_code_hash,
    runtime_api::api::{
        self,
        contracts::events::CodeRemoved,
    },
    submit_extrinsic,
    Client,
    CodeHash,
    ContractMessageTranscoder,
    DefaultConfig,
    ErrorVariant,
    ExtrinsicOpts,
    ExtrinsicOptsBuilder,
    PairSigner,
    TokenMetadata,
};
use anyhow::Result;
use std::fmt::Debug;
use subxt::{
    Config,
    OnlineClient,
};
use tokio::runtime::Runtime;

#[derive(Debug, clap::Args)]
#[clap(name = "remove", about = "Remove a contract's code")]
pub struct RemoveCommand {
    /// The hash of the smart contract code already uploaded to the chain.
    #[clap(long, value_parser = parse_code_hash)]
    code_hash: Option<<DefaultConfig as Config>::Hash>,
    #[clap(flatten)]
    extrinsic_opts: ExtrinsicOpts,
    /// Export the call output as JSON.
    #[clap(long, conflicts_with = "verbose")]
    output_json: bool,
}

/// A builder for RemoveCommand.
pub struct RemoveCommandBuilder {
    code_hash: Option<<DefaultConfig as Config>::Hash>,
    extrinsic_opts: ExtrinsicOptsBuilder,
    output_json: bool,
}

impl RemoveCommandBuilder {
    /// Creates a new RemoveCommandBuilder with default values.
    pub fn new() -> Self {
        RemoveCommandBuilder {
            code_hash: None,
            extrinsic_opts: ExtrinsicOptsBuilder::default(),
            output_json: false,
        }
    }

    /// Sets the hash of the smart contract code already uploaded to the chain.
    pub fn code_hash(
        mut self,
        code_hash: Option<<DefaultConfig as Config>::Hash>,
    ) -> Self {
        self.code_hash = code_hash;
        self
    }

    /// Sets the extrinsic options.
    pub fn extrinsic_opts(mut self, extrinsic_opts: ExtrinsicOptsBuilder) -> Self {
        self.extrinsic_opts = extrinsic_opts;
        self
    }

    /// Sets whether to export the call output as JSON.
    pub fn output_json(mut self, output_json: bool) -> Self {
        self.output_json = output_json;
        self
    }

    /// Builds and returns a RemoveCommand instance with the configured values.
    pub fn build(self) -> RemoveCommand {
        RemoveCommand {
            code_hash: self.code_hash,
            extrinsic_opts: self.extrinsic_opts.done(),
            output_json: self.output_json,
        }
    }
}

impl Default for RemoveCommandBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RemoveCommand {
    pub fn is_json(&self) -> bool {
        self.output_json
    }

    pub fn run(&self) -> Result<(), ErrorVariant> {
        let artifacts = self.extrinsic_opts.contract_artifacts()?;
        let transcoder = artifacts.contract_transcoder()?;
        let signer = super::pair_signer(self.extrinsic_opts.signer()?);

        let artifacts_path = artifacts.artifact_path().to_path_buf();

        let final_code_hash = match (self.code_hash.as_ref(), artifacts.code.as_ref()) {
            (Some(code_h), _) => {
                Ok(code_h.0)
            }
            (None, Some(_)) => {
                artifacts.code_hash()
            }
            (None, None) => {
                Err(anyhow::anyhow!(
                    "No code_hash was provided or contract code was not found from artifact \
                     file {}. Please provide a code hash with --code-hash argument or specify the \
                     path for artifacts files with --manifest-path",
                    artifacts_path.display()
                ))
            }
        }?;

        Runtime::new()?.block_on(async {
            let url = self.extrinsic_opts.url_to_string();
            let client = OnlineClient::from_url(url.clone()).await?;
            if let Some(code_removed) = self
                .remove_code(
                    &client,
                    sp_core::H256(final_code_hash),
                    &signer,
                    &transcoder,
                )
                .await?
            {
                let remove_result = code_removed.code_hash;

                if self.output_json {
                    println!("{}", &remove_result);
                } else {
                    name_value_println!("Code hash", format!("{remove_result:?}"));
                }
                Result::<(), ErrorVariant>::Ok(())
            } else {
                let error_code_hash = hex::encode(final_code_hash);
                Err(anyhow::anyhow!(
                    "Error removing the code for the supplied code hash: {}",
                    error_code_hash
                )
                .into())
            }
        })
    }

    async fn remove_code(
        &self,
        client: &Client,
        code_hash: CodeHash,
        signer: &PairSigner,
        transcoder: &ContractMessageTranscoder,
    ) -> Result<Option<CodeRemoved>, ErrorVariant> {
        let call = api::tx()
            .contracts()
            .remove_code(sp_core::H256(code_hash.0));

        let result = submit_extrinsic(client, &call, signer).await?;
        let display_events =
            DisplayEvents::from_events(&result, Some(transcoder), &client.metadata())?;

        let output = if self.output_json {
            display_events.to_json()?
        } else {
            let token_metadata = TokenMetadata::query(client).await?;
            display_events
                .display_events(self.extrinsic_opts.verbosity()?, &token_metadata)?
        };
        println!("{output}");
        let code_removed = result.find_first::<CodeRemoved>()?;
        Ok(code_removed)
    }
}
