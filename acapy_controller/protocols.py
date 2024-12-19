"""Defintions of protocols flows."""

import asyncio
from dataclasses import dataclass
import logging
from secrets import randbelow, token_hex
from typing import Any, Dict, List, Mapping, Optional, Tuple, Type, Union
from uuid import uuid4

from .controller import Controller, ControllerError, MinType, Minimal, params
from .onboarding import get_onboarder


LOGGER = logging.getLogger(__name__)


@dataclass
class ConnRecord(Minimal):
    """Connection record."""

    connection_id: str
    invitation_key: str
    state: str
    rfc23_state: str


async def trustping(
    sender: Controller, conn: ConnRecord, comment: Optional[str] = None
):
    """Send a trustping to the specified connection."""
    await sender.post(
        f"/connections/{conn.connection_id}/send-ping",
        json={"comment": comment or "Ping!"},
    )


@dataclass
class InvitationResult(Minimal):
    """Result of creating a connection invitation."""

    invitation: dict
    connection_id: str


async def connection_invitation(
    inviter: Controller,
    *,
    use_public_did: bool = False,
    multi_use: Optional[bool] = None,
):
    """Create a connection invitation.

    This will always create an invite with auto_accept set to false to simplify
    the connection function below.
    """
    invitation = await inviter.post(
        "/connections/create-invitation",
        json={},
        params=params(auto_accept=False, multi_use=multi_use, public=use_public_did),
        response=InvitationResult,
    )
    return invitation


async def connection(
    inviter: Controller,
    invitee: Controller,
    *,
    invitation: Optional[InvitationResult] = None,
):
    """Connect two agents."""

    if invitation is None:
        invitation = await connection_invitation(inviter)

    inviter_conn = await inviter.get(
        f"/connections/{invitation.connection_id}",
        response=ConnRecord,
    )

    invitee_conn = await invitee.post(
        "/connections/receive-invitation",
        json=invitation.invitation,
        response=ConnRecord,
    )

    await invitee.post(
        f"/connections/{invitee_conn.connection_id}/accept-invitation",
    )

    inviter_conn = await inviter.event_with_values(
        topic="connections",
        invitation_key=inviter_conn.invitation_key,
        state="request",
        event_type=ConnRecord,
    )

    inviter_conn = await inviter.post(
        f"/connections/{inviter_conn.connection_id}/accept-request",
        response=ConnRecord,
    )

    await invitee.event_with_values(
        topic="connections",
        connection_id=invitee_conn.connection_id,
        rfc23_state="response-received",
    )
    await invitee.post(
        f"/connections/{invitee_conn.connection_id}/send-ping",
        json={"comment": "Making connection active"},
    )

    inviter_conn = await inviter.event_with_values(
        topic="connections",
        event_type=ConnRecord,
        connection_id=inviter_conn.connection_id,
        rfc23_state="completed",
    )
    invitee_conn = await invitee.event_with_values(
        topic="connections",
        event_type=ConnRecord,
        connection_id=invitee_conn.connection_id,
        rfc23_state="completed",
    )

    return inviter_conn, invitee_conn


@dataclass
class InvitationMessage(Minimal):
    """Invitation message."""

    @property
    def id(self) -> str:
        """Return the invitation id."""
        return self._extra["@id"]


@dataclass
class InvitationRecord(Minimal):
    """Invitation record."""

    invitation: InvitationMessage

    @classmethod
    def deserialize(cls: Type[MinType], value: Mapping[str, Any]) -> MinType:
        """Deserialize the invitation record."""
        value = dict(value)
        if invitation := value.get("invitation"):
            value["invitation"] = InvitationMessage.deserialize(invitation)
        return super().deserialize(value)


async def oob_invitation(
    inviter: Controller,
    *,
    use_public_did: bool = False,
    multi_use: Optional[bool] = None,
) -> InvitationMessage:
    """Create an OOB invitation.

    This will always create an invite with auto_accept set to false to simplify
    the didexchange function below.
    """
    invite_record = await inviter.post(
        "/out-of-band/create-invitation",
        json={
            "handshake_protocols": ["https://didcomm.org/didexchange/1.0"],
            "use_public_did": use_public_did,
        },
        params=params(
            auto_accept=False,
            multi_use=multi_use,
        ),
        response=InvitationRecord,
    )
    return invite_record.invitation


@dataclass
class OobRecord(Minimal):
    """Out-of-band record."""

    connection_id: str
    our_recipient_key: Optional[str] = None


async def didexchange(
    inviter: Controller,
    invitee: Controller,
    *,
    invite: Optional[InvitationMessage] = None,
    use_existing_connection: bool = False,
    alias: Optional[str] = None,
):
    """Connect two agents using did exchange protocol."""
    if not invite:
        invite = await oob_invitation(inviter)

    invitee_oob_record = await invitee.post(
        "/out-of-band/receive-invitation",
        json=invite,
        params=params(
            use_existing_connection=use_existing_connection,
            alias=alias,
        ),
        response=OobRecord,
    )

    if use_existing_connection and invitee_oob_record == "reuse-accepted":
        inviter_oob_record = await inviter.event_with_values(
            topic="out_of_band",
            invi_msg_id=invite.id,
            event_type=OobRecord,
        )
        inviter_conn = await inviter.get(
            f"/connections/{inviter_oob_record.connection_id}",
            response=ConnRecord,
        )
        invitee_conn = await invitee.get(
            f"/connections/{invitee_oob_record.connection_id}",
            response=ConnRecord,
        )
        return inviter_conn, invitee_conn

    invitee_conn = await invitee.post(
        f"/didexchange/{invitee_oob_record.connection_id}/accept-invitation",
        response=ConnRecord,
    )
    inviter_oob_record = await inviter.event_with_values(
        topic="out_of_band",
        invi_msg_id=invite.id,
        state="done",
        event_type=OobRecord,
    )
    inviter_conn = await inviter.event_with_values(
        topic="connections",
        event_type=ConnRecord,
        rfc23_state="request-received",
        invitation_key=inviter_oob_record.our_recipient_key,
    )
    # TODO Remove after ACA-Py 0.12.0
    # There's a bug with race conditions in the OOB multiuse handling
    await asyncio.sleep(1)
    inviter_conn = await inviter.post(
        f"/didexchange/{inviter_conn.connection_id}/accept-request",
        response=ConnRecord,
    )

    await invitee.event_with_values(
        topic="connections",
        connection_id=invitee_conn.connection_id,
        rfc23_state="response-received",
    )
    invitee_conn = await invitee.event_with_values(
        topic="connections",
        connection_id=invitee_conn.connection_id,
        rfc23_state="completed",
        event_type=ConnRecord,
    )
    inviter_conn = await inviter.event_with_values(
        topic="connections",
        connection_id=inviter_conn.connection_id,
        rfc23_state="completed",
        event_type=ConnRecord,
    )

    return inviter_conn, invitee_conn


@dataclass
class MediationRecord(Minimal):
    """Mediation record."""

    mediation_id: str
    connection_id: str


async def request_mediation_v1(
    mediator: Controller,
    client: Controller,
    mediator_connection_id: str,
    client_connection_id: str,
):
    """Request mediation and await mediation granted."""
    client_record = await client.post(
        f"/mediation/request/{client_connection_id}",
        response=MediationRecord,
    )
    mediator_record = await mediator.event_with_values(
        topic="mediation",
        connection_id=mediator_connection_id,
        event_type=MediationRecord,
    )
    await mediator.post(f"/mediation/requests/{mediator_record.mediation_id}/grant")
    client_record = await client.event_with_values(
        topic="mediation",
        connection_id=client_connection_id,
        mediation_id=client_record.mediation_id,
        state="granted",
        event_type=MediationRecord,
    )
    mediator_record = await mediator.event_with_values(
        topic="mediation",
        connection_id=mediator_connection_id,
        mediation_id=mediator_record.mediation_id,
        state="granted",
        event_type=MediationRecord,
    )
    return mediator_record, client_record


@dataclass
class DIDInfo(Minimal):
    """DID information."""

    did: str
    verkey: str


@dataclass
class DIDResult(Minimal):
    """Result of creating a DID."""

    result: Optional[DIDInfo]

    @classmethod
    def deserialize(cls: Type[MinType], value: Mapping[str, Any]) -> MinType:
        """Deserialize the DID result."""
        value = dict(value)
        if result := value.get("result"):
            value["result"] = DIDInfo.deserialize(result)
        return super().deserialize(value)


async def indy_anoncred_onboard(agent: Controller):
    """Onboard agent for indy anoncred operations."""

    config = (await agent.get("/status/config"))["config"]
    genesis_url = config.get("ledger.genesis_url")

    if not genesis_url:
        raise ControllerError("No ledger configured on agent")

    taa = (await agent.get("/ledger/taa"))["result"]
    if taa.get("taa_required") is True and taa.get("taa_accepted") is None:
        await agent.post(
            "/ledger/taa/accept",
            json={
                "mechanism": "on_file",
                "text": taa["taa_record"]["text"],
                "version": taa["taa_record"]["version"],
            },
        )

    public_did = (await agent.get("/wallet/did/public", response=DIDResult)).result
    if not public_did:
        public_did = (
            await agent.post(
                "/wallet/did/create",
                json={"method": "sov", "options": {"key_type": "ed25519"}},
                response=DIDResult,
            )
        ).result
        assert public_did

        onboarder = get_onboarder(genesis_url)
        if not onboarder:
            raise ControllerError("Unrecognized ledger, cannot automatically onboard")
        await onboarder.onboard(public_did.did, public_did.verkey)

        await agent.post("/wallet/did/public", params=params(did=public_did.did))

    return public_did


@dataclass
class SchemaResult(Minimal):
    """Result of creating a schema."""

    schema_id: str


@dataclass
class CredDefResult(Minimal):
    """Result of creating a credential definition."""

    credential_definition_id: str


async def indy_anoncred_credential_artifacts(
    agent: Controller,
    attributes: List[str],
    schema_name: Optional[str] = None,
    schema_version: Optional[str] = None,
    cred_def_tag: Optional[str] = None,
    support_revocation: bool = False,
    revocation_registry_size: Optional[int] = None,
):
    """Prepare credential artifacts for indy anoncreds."""
    schema = await agent.post(
        "/schemas",
        json={
            "schema_name": schema_name or "minimal-" + token_hex(8),
            "schema_version": schema_version or "1.0",
            "attributes": attributes,
        },
        response=SchemaResult,
    )

    cred_def = await agent.post(
        "/credential-definitions",
        json={
            "revocation_registry_size": (
                revocation_registry_size if revocation_registry_size else 10
            ),
            "schema_id": schema.schema_id,
            "support_revocation": support_revocation,
            "tag": cred_def_tag or token_hex(8),
        },
        response=CredDefResult,
    )

    return schema, cred_def


@dataclass
class V10CredentialExchange(Minimal):
    """V1.0 credential exchange record."""

    state: str
    credential_exchange_id: str
    connection_id: str
    thread_id: str
    credential_definition_id: str
    revoc_reg_id: Optional[str] = None
    revocation_id: Optional[str] = None


async def indy_issue_credential_v1(
    issuer: Controller,
    holder: Controller,
    issuer_connection_id: str,
    holder_connection_id: str,
    cred_def_id: str,
    attributes: Mapping[str, str],
) -> Tuple[V10CredentialExchange, V10CredentialExchange]:
    """Issue an indy credential using issue-credential/1.0.

    Issuer and holder should already be connected.
    """
    issuer_cred_ex = await issuer.post(
        "/issue-credential/send-offer",
        json={
            "auto_issue": False,
            "auto_remove": False,
            "comment": "Credential from minimal example",
            "trace": False,
            "connection_id": issuer_connection_id,
            "cred_def_id": cred_def_id,
            "credential_preview": {
                "type": "issue-credential/1.0/credential-preview",
                "attributes": [
                    {
                        "mime_type": None,
                        "name": name,
                        "value": value,
                    }
                    for name, value in attributes.items()
                ],
            },
        },
        response=V10CredentialExchange,
    )
    issuer_cred_ex_id = issuer_cred_ex.credential_exchange_id

    holder_cred_ex = await holder.event_with_values(
        topic="issue_credential",
        event_type=V10CredentialExchange,
        connection_id=holder_connection_id,
        state="offer_received",
    )
    holder_cred_ex_id = holder_cred_ex.credential_exchange_id

    holder_cred_ex = await holder.post(
        f"/issue-credential/records/{holder_cred_ex_id}/send-request",
        response=V10CredentialExchange,
    )

    await issuer.event_with_values(
        topic="issue_credential",
        credential_exchange_id=issuer_cred_ex_id,
        state="request_received",
    )

    # TODO Remove after ACA-Py 0.12.0
    # Race condition in DB commit vs webhook emit
    await asyncio.sleep(1)
    issuer_cred_ex = await issuer.post(
        f"/issue-credential/records/{issuer_cred_ex_id}/issue",
        json={},
        response=V10CredentialExchange,
    )

    await holder.event_with_values(
        topic="issue_credential",
        credential_exchange_id=holder_cred_ex_id,
        state="credential_received",
    )

    holder_cred_ex = await holder.post(
        f"/issue-credential/records/{holder_cred_ex_id}/store",
        json={},
        response=V10CredentialExchange,
    )
    issuer_cred_ex = await issuer.event_with_values(
        topic="issue_credential",
        event_type=V10CredentialExchange,
        credential_exchange_id=issuer_cred_ex_id,
        state="credential_acked",
    )

    holder_cred_ex = await holder.event_with_values(
        topic="issue_credential",
        event_type=V10CredentialExchange,
        credential_exchange_id=holder_cred_ex_id,
        state="credential_acked",
    )

    return issuer_cred_ex, holder_cred_ex


@dataclass
class V20CredExRecord(Minimal):
    """V2.0 credential exchange record."""

    state: str
    cred_ex_id: str
    connection_id: str
    thread_id: str


@dataclass
class V20CredExRecordIndy(Minimal):
    """V2.0 credential exchange record indy."""

    rev_reg_id: Optional[str] = None
    cred_rev_id: Optional[str] = None


@dataclass
class V20CredExRecordDetail(Minimal):
    """V2.0 credential exchange record detail."""

    cred_ex_record: V20CredExRecord
    indy: Optional[V20CredExRecordIndy] = None


async def indy_issue_credential_v2(
    issuer: Controller,
    holder: Controller,
    issuer_connection_id: str,
    holder_connection_id: str,
    cred_def_id: str,
    attributes: Mapping[str, str],
) -> Tuple[V20CredExRecordDetail, V20CredExRecordDetail]:
    """Issue an indy credential using issue-credential/2.0.

    Issuer and holder should already be connected.
    """

    issuer_cred_ex = await issuer.post(
        "/issue-credential-2.0/send-offer",
        json={
            "auto_issue": False,
            "auto_remove": False,
            "comment": "Credential from minimal example",
            "trace": False,
            "connection_id": issuer_connection_id,
            "filter": {"indy": {"cred_def_id": cred_def_id}},
            "credential_preview": {
                "type": "issue-credential-2.0/2.0/credential-preview",  # pyright: ignore
                "attributes": [
                    {
                        "mime_type": None,
                        "name": name,
                        "value": value,
                    }
                    for name, value in attributes.items()
                ],
            },
        },
        response=V20CredExRecord,
    )
    issuer_cred_ex_id = issuer_cred_ex.cred_ex_id

    holder_cred_ex = await holder.event_with_values(
        topic="issue_credential_v2_0",
        event_type=V20CredExRecord,
        connection_id=holder_connection_id,
        state="offer-received",
    )
    holder_cred_ex_id = holder_cred_ex.cred_ex_id

    holder_cred_ex = await holder.post(
        f"/issue-credential-2.0/records/{holder_cred_ex_id}/send-request",
        response=V20CredExRecord,
    )

    await issuer.event_with_values(
        topic="issue_credential_v2_0",
        cred_ex_id=issuer_cred_ex_id,
        state="request-received",
    )

    issuer_cred_ex = await issuer.post(
        f"/issue-credential-2.0/records/{issuer_cred_ex_id}/issue",
        json={},
        response=V20CredExRecordDetail,
    )

    await holder.event_with_values(
        topic="issue_credential_v2_0",
        cred_ex_id=holder_cred_ex_id,
        state="credential-received",
    )

    holder_cred_ex = await holder.post(
        f"/issue-credential-2.0/records/{holder_cred_ex_id}/store",
        json={},
        response=V20CredExRecordDetail,
    )
    issuer_cred_ex = await issuer.event_with_values(
        topic="issue_credential_v2_0",
        event_type=V20CredExRecord,
        cred_ex_id=issuer_cred_ex_id,
        state="done",
    )
    issuer_indy_record = await issuer.event_with_values(
        topic="issue_credential_v2_0_indy",
        event_type=V20CredExRecordIndy,
    )

    holder_cred_ex = await holder.event_with_values(
        topic="issue_credential_v2_0",
        event_type=V20CredExRecord,
        cred_ex_id=holder_cred_ex_id,
        state="done",
    )
    holder_indy_record = await holder.event_with_values(
        topic="issue_credential_v2_0_indy",
        event_type=V20CredExRecordIndy,
    )

    return (
        V20CredExRecordDetail(cred_ex_record=issuer_cred_ex, indy=issuer_indy_record),
        V20CredExRecordDetail(
            cred_ex_record=holder_cred_ex,
            indy=holder_indy_record,
        ),
    )


@dataclass
class IndyProofRequest(Minimal):
    """Indy proof request."""

    requested_attributes: Dict[str, Any]
    requested_predicates: Dict[str, Any]


@dataclass
class IndyPresSpec(Minimal):
    """Indy presentation specification."""

    requested_attributes: Dict[str, Any]
    requested_predicates: Dict[str, Any]
    self_attested_attributes: Dict[str, Any]


@dataclass
class IndyCredInfo(Minimal):
    """Indy credential information."""

    referent: str
    attrs: Dict[str, Any]


@dataclass
class IndyCredPrecis(Minimal):
    """Indy credential precis."""

    cred_info: IndyCredInfo
    presentation_referents: List[str]

    @classmethod
    def deserialize(cls: Type[MinType], value: Mapping[str, Any]) -> MinType:
        """Deserialize the credential precis."""
        value = dict(value)
        if cred_info := value.get("cred_info"):
            value["cred_info"] = IndyCredInfo.deserialize(cred_info)
        return super().deserialize(value)


def indy_auto_select_credentials_for_presentation_request(
    presentation_request: Union[IndyProofRequest, dict],
    relevant_creds: List[IndyCredPrecis],
) -> IndyPresSpec:
    """Select credentials to use for presentation automatically."""
    if isinstance(presentation_request, dict):
        presentation_request = IndyProofRequest.deserialize(presentation_request)

    requested_attributes = {}
    for pres_referrent in presentation_request.requested_attributes.keys():
        for cred_precis in relevant_creds:
            if pres_referrent in cred_precis.presentation_referents:
                requested_attributes[pres_referrent] = {
                    "cred_id": cred_precis.cred_info.referent,
                    "revealed": True,
                }
    requested_predicates = {}
    for pres_referrent in presentation_request.requested_predicates.keys():
        for cred_precis in relevant_creds:
            if pres_referrent in cred_precis.presentation_referents:
                requested_predicates[pres_referrent] = {
                    "cred_id": cred_precis.cred_info.referent,
                }

    return IndyPresSpec.deserialize(
        {
            "requested_attributes": requested_attributes,
            "requested_predicates": requested_predicates,
            "self_attested_attributes": {},
        }
    )


@dataclass
class V10PresentationExchange(Minimal):
    """V1.0 presentation exchange record."""

    state: str
    presentation_exchange_id: str
    connection_id: str
    thread_id: str
    presentation_request: dict


async def indy_present_proof_v1(
    holder: Controller,
    verifier: Controller,
    holder_connection_id: str,
    verifier_connection_id: str,
    *,
    name: Optional[str] = None,
    version: Optional[str] = None,
    comment: Optional[str] = None,
    requested_attributes: Optional[List[Mapping[str, Any]]] = None,
    requested_predicates: Optional[List[Mapping[str, Any]]] = None,
    non_revoked: Optional[Mapping[str, int]] = None,
):
    """Present an Indy credential using present proof v1."""
    verifier_pres_ex = await verifier.post(
        "/present-proof/send-request",
        json={
            "auto_verify": False,
            "comment": comment or "Presentation request from minimal",
            "connection_id": verifier_connection_id,
            "proof_request": {
                "name": name or "proof",
                "version": version or "0.1.0",
                "nonce": str(randbelow(10**10)),
                "requested_attributes": {
                    str(uuid4()): attr for attr in requested_attributes or []
                },
                "requested_predicates": {
                    str(uuid4()): pred for pred in requested_predicates or []
                },
                "non_revoked": (non_revoked if non_revoked else None),
            },
            "trace": False,
        },
        response=V10PresentationExchange,
    )
    verifier_pres_ex_id = verifier_pres_ex.presentation_exchange_id

    holder_pres_ex = await holder.event_with_values(
        topic="present_proof",
        event_type=V10PresentationExchange,
        connection_id=holder_connection_id,
        state="request_received",
    )
    assert holder_pres_ex.presentation_request
    holder_pres_ex_id = holder_pres_ex.presentation_exchange_id

    relevant_creds = await holder.get(
        f"/present-proof/records/{holder_pres_ex_id}/credentials",
        response=List[IndyCredPrecis],
    )
    pres_spec = indy_auto_select_credentials_for_presentation_request(
        holder_pres_ex.presentation_request, relevant_creds
    )
    holder_pres_ex = await holder.post(
        f"/present-proof/records/{holder_pres_ex_id}/send-presentation",
        json=pres_spec,
        response=V10PresentationExchange,
    )

    await verifier.event_with_values(
        topic="present_proof",
        event_type=V10PresentationExchange,
        presentation_exchange_id=verifier_pres_ex_id,
        state="presentation_received",
    )
    verifier_pres_ex = await verifier.post(
        f"/present-proof/records/{verifier_pres_ex_id}/verify-presentation",
        json={},
        response=V10PresentationExchange,
    )
    verifier_pres_ex = await verifier.event_with_values(
        topic="present_proof",
        event_type=V10PresentationExchange,
        presentation_exchange_id=verifier_pres_ex_id,
        state="verified",
    )

    holder_pres_ex = await holder.event_with_values(
        topic="present_proof",
        event_type=V10PresentationExchange,
        presentation_exchange_id=holder_pres_ex_id,
        state="presentation_acked",
    )

    return holder_pres_ex, verifier_pres_ex


@dataclass
class ByFormat(Minimal):
    """By format."""

    pres_request: Optional[dict] = None


@dataclass
class V20PresExRecord(Minimal):
    """V2.0 presentation exchange record."""

    state: str
    pres_ex_id: str
    connection_id: str
    thread_id: str
    by_format: ByFormat
    pres_request: Optional[dict] = None

    @classmethod
    def deserialize(cls: Type[MinType], value: Mapping[str, Any]) -> MinType:
        """Deserialize the presentation exchange record."""
        value = dict(value)
        if by_format := value.get("by_format"):
            value["by_format"] = ByFormat.deserialize(by_format)
        return super().deserialize(value)


async def indy_present_proof_v2(
    holder: Controller,
    verifier: Controller,
    holder_connection_id: str,
    verifier_connection_id: str,
    *,
    name: Optional[str] = None,
    version: Optional[str] = None,
    comment: Optional[str] = None,
    requested_attributes: Optional[List[Mapping[str, Any]]] = None,
    requested_predicates: Optional[List[Mapping[str, Any]]] = None,
    non_revoked: Optional[Mapping[str, int]] = None,
):
    """Present an Indy credential using present proof v2."""
    verifier_pres_ex = await verifier.post(
        "/present-proof-2.0/send-request",
        json={
            "auto_verify": False,
            "comment": comment or "Presentation request from minimal",
            "connection_id": verifier_connection_id,
            "presentation_request": {
                "indy": {
                    "name": name or "proof",
                    "version": version or "0.1.0",
                    "nonce": str(randbelow(10**10)),
                    "requested_attributes": {
                        str(uuid4()): attr for attr in requested_attributes or []
                    },
                    "requested_predicates": {
                        str(uuid4()): pred for pred in requested_predicates or []
                    },
                    "non_revoked": (non_revoked if non_revoked else None),
                },
            },
            "trace": False,
        },
        response=V20PresExRecord,
    )
    verifier_pres_ex_id = verifier_pres_ex.pres_ex_id

    holder_pres_ex = await holder.event_with_values(
        topic="present_proof_v2_0",
        event_type=V20PresExRecord,
        connection_id=holder_connection_id,
        state="request-received",
    )
    assert holder_pres_ex.pres_request
    holder_pres_ex_id = holder_pres_ex.pres_ex_id

    relevant_creds = await holder.get(
        f"/present-proof-2.0/records/{holder_pres_ex_id}/credentials",
        response=List[IndyCredPrecis],
    )
    assert holder_pres_ex.by_format.pres_request
    indy_proof_request = holder_pres_ex.by_format.pres_request["indy"]
    pres_spec = indy_auto_select_credentials_for_presentation_request(
        indy_proof_request, relevant_creds
    )
    holder_pres_ex = await holder.post(
        f"/present-proof-2.0/records/{holder_pres_ex_id}/send-presentation",
        json={
            "indy": pres_spec.serialize(),
            "trace": False,
        },
        response=V20PresExRecord,
    )

    await verifier.event_with_values(
        topic="present_proof_v2_0",
        event_type=V20PresExRecord,
        pres_ex_id=verifier_pres_ex_id,
        state="presentation-received",
    )
    verifier_pres_ex = await verifier.post(
        f"/present-proof-2.0/records/{verifier_pres_ex_id}/verify-presentation",
        json={},
        response=V20PresExRecord,
    )
    verifier_pres_ex = await verifier.event_with_values(
        topic="present_proof_v2_0",
        event_type=V20PresExRecord,
        pres_ex_id=verifier_pres_ex_id,
        state="done",
    )

    holder_pres_ex = await holder.event_with_values(
        topic="present_proof_v2_0",
        event_type=V20PresExRecord,
        pres_ex_id=holder_pres_ex_id,
        state="done",
    )

    return holder_pres_ex, verifier_pres_ex


async def indy_anoncreds_revoke(
    issuer: Controller,
    cred_ex: Union[V10CredentialExchange, V20CredExRecordDetail],
    holder_connection_id: Optional[str] = None,
    publish: bool = False,
    notify: bool = True,
    notify_version: str = "v1_0",
):
    """Revoking an Indy credential using revocation revoke.

    V1.0: V10CredentialExchange
    V2.0: V20CredExRecordDetail.
    """
    if notify and holder_connection_id is None:
        return (
            "If you are going to set notify to True,"
            "then holder_connection_id cannot be empty."
        )

    # Passes in V10CredentialExchange
    if isinstance(cred_ex, V10CredentialExchange):
        await issuer.post(
            url="/revocation/revoke",
            json={
                "connection_id": holder_connection_id,
                "rev_reg_id": cred_ex.revoc_reg_id,
                "cred_rev_id": cred_ex.revocation_id,
                "publish": publish,
                "notify": notify,
                "notify_version": notify_version,
            },
        )

    # Passes in V20CredExRecordDetail
    elif isinstance(cred_ex, V20CredExRecordDetail) and cred_ex.indy:
        await issuer.post(
            url="/revocation/revoke",
            json={
                "connection_id": holder_connection_id,
                "rev_reg_id": cred_ex.indy.rev_reg_id,
                "cred_rev_id": cred_ex.indy.cred_rev_id,
                "publish": publish,
                "notify": notify,
                "notify_version": notify_version,
            },
        )

    else:
        raise TypeError(
            "Expected cred_ex to be V10CredentialExchange or V20CredExRecordDetail; "
            f"got {type(cred_ex).__name__}"
        )


async def indy_anoncreds_publish_revocation(
    issuer: Controller,
    cred_ex: Union[V10CredentialExchange, V20CredExRecordDetail],
    publish: bool = False,
    notify: bool = True,
):
    """Publishing revocation of indy credential.

    V1.0: V10CredentialExchange
    V2.0: V20CredExRecordDetail.
    """
    if isinstance(cred_ex, V10CredentialExchange):
        await issuer.post(
            url="/revocation/publish-revocations",
            json={
                "rev_reg_id": cred_ex.revoc_reg_id,
                "cred_rev_id": cred_ex.revocation_id,
                "publish": publish,
                "notify": notify,
            },
        )

    elif isinstance(cred_ex, V20CredExRecordDetail) and cred_ex.indy:
        await issuer.post(
            url="/revocation/publish-revocations",
            json={
                "rev_reg_id": cred_ex.indy.rev_reg_id,
                "cred_rev_id": cred_ex.indy.cred_rev_id,
                "publish": publish,
                "notify": notify,
            },
        )

    else:
        raise TypeError(
            "Expected cred_ex to be V10CredentialExchange or V20CredExRecordDetail; "
            f"got {type(cred_ex).__name__}"
        )


async def jsonld_issue_credential(
    issuer: Controller,
    holder: Controller,
    issuer_connection_id: str,
    holder_connection_id: str,
    credential: Mapping[str, Any],
    options: Mapping[str, Any],
):
    """Issue a JSON-LD Credential."""
    issuer_cred_ex = await issuer.post(
        "/issue-credential-2.0/send-offer",
        json={
            "auto_issue": False,
            "auto_remove": False,
            "comment": "Credential from minimal example",
            "trace": False,
            "connection_id": issuer_connection_id,
            "filter": {
                "ld_proof": {
                    "credential": credential,
                    "options": options,
                }
            },
        },
        response=V20CredExRecord,
    )
    issuer_cred_ex_id = issuer_cred_ex.cred_ex_id

    holder_cred_ex = await holder.event_with_values(
        topic="issue_credential_v2_0",
        event_type=V20CredExRecord,
        connection_id=holder_connection_id,
        state="offer-received",
    )
    holder_cred_ex_id = holder_cred_ex.cred_ex_id

    holder_cred_ex = await holder.post(
        f"/issue-credential-2.0/records/{holder_cred_ex_id}/send-request",
        response=V20CredExRecord,
    )

    await issuer.event_with_values(
        topic="issue_credential_v2_0",
        cred_ex_id=issuer_cred_ex_id,
        state="request-received",
    )

    issuer_cred_ex = await issuer.post(
        f"/issue-credential-2.0/records/{issuer_cred_ex_id}/issue",
        json={},
        response=V20CredExRecordDetail,
    )

    await holder.event_with_values(
        topic="issue_credential_v2_0",
        cred_ex_id=holder_cred_ex_id,
        state="credential-received",
    )

    holder_cred_ex = await holder.post(
        f"/issue-credential-2.0/records/{holder_cred_ex_id}/store",
        json={},
        response=V20CredExRecordDetail,
    )
    issuer_cred_ex = await issuer.event_with_values(
        topic="issue_credential_v2_0",
        event_type=V20CredExRecord,
        cred_ex_id=issuer_cred_ex_id,
        state="done",
    )

    holder_cred_ex = await holder.event_with_values(
        topic="issue_credential_v2_0",
        event_type=V20CredExRecord,
        cred_ex_id=holder_cred_ex_id,
        state="done",
    )

    return issuer_cred_ex, holder_cred_ex


async def jsonld_present_proof(
    verifier: Controller,
    holder: Controller,
    verifier_connection_id: str,
    holder_connection_id: str,
    presentation_definition: Mapping[str, Any],
    domain: str,
    *,
    comment: Optional[str] = None,
):
    """Present an Indy credential using present proof v1."""
    verifier_pres_ex = await verifier.post(
        "/present-proof-2.0/send-request",
        json={
            "auto_verify": False,
            "comment": comment or "Presentation request from minimal",
            "connection_id": verifier_connection_id,
            "presentation_request": {
                "dif": {
                    "presentation_definition": presentation_definition,
                    "options": {"challenge": str(uuid4()), "domain": domain},
                },
            },
            "trace": False,
        },
        response=V20PresExRecord,
    )
    verifier_pres_ex_id = verifier_pres_ex.pres_ex_id

    holder_pres_ex = await holder.event_with_values(
        topic="present_proof_v2_0",
        event_type=V20PresExRecord,
        connection_id=holder_connection_id,
        state="request-received",
    )
    assert holder_pres_ex.pres_request
    assert "request_presentations~attach" in holder_pres_ex.pres_request
    assert holder_pres_ex.pres_request["request_presentations~attach"]
    attachment = holder_pres_ex.pres_request["request_presentations~attach"][0]
    assert "data" in attachment
    assert "json" in attachment["data"]
    assert "presentation_definition" in attachment["data"]["json"]
    definition = attachment["data"]["json"]["presentation_definition"]
    holder_pres_ex_id = holder_pres_ex.pres_ex_id

    holder_pres_ex = await holder.post(
        f"/present-proof-2.0/records/{holder_pres_ex_id}/send-presentation",
        json={"dif": {"presentation_definition": definition}},
        response=V20PresExRecord,
    )

    await verifier.event_with_values(
        topic="present_proof_v2_0",
        event_type=V20PresExRecord,
        pres_ex_id=verifier_pres_ex_id,
        state="presentation-received",
    )
    verifier_pres_ex = await verifier.post(
        f"/present-proof-2.0/records/{verifier_pres_ex_id}/verify-presentation",
        json={},
        response=V20PresExRecord,
    )
    verifier_pres_ex = await verifier.event_with_values(
        topic="present_proof_v2_0",
        event_type=V20PresExRecord,
        pres_ex_id=verifier_pres_ex_id,
        state="done",
    )

    holder_pres_ex = await holder.event_with_values(
        topic="present_proof_v2_0",
        event_type=V20PresExRecord,
        pres_ex_id=holder_pres_ex_id,
        state="done",
    )

    return verifier_pres_ex, holder_pres_ex
