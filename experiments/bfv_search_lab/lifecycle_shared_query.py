"""Q76 local durable authorization, separate from the public native predicate.

Trusted local code/filesystem and non-rollback storage are explicit premises.
This is not an attested remote release protocol. The public authorizer has no
HE secret or callback; a separate local guard may dispatch a trusted hook.
The hook result is never returned, and a failed/crashed dispatch stays consumed.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import secrets
import sqlite3

from experiments.bfv_search_lab import authenticated_shared_query as auth
from experiments.bfv_search_lab import native_shared_query as native

APPLICATION_ID = 0x43513736
SCHEMA_VERSION = 1
STATES = ("reserved", "rejected", "authorized", "dispatch_started", "delivered", "callback_failed")
_SCHEMA = {
    "configuration": """CREATE TABLE configuration (
      slot INTEGER PRIMARY KEY CHECK(slot=1),
      owner BLOB NOT NULL CHECK(length(owner)=32),
      policy BLOB NOT NULL CHECK(length(policy)=32),
      scope BLOB NOT NULL CHECK(length(scope)=32),
      code BLOB NOT NULL CHECK(length(code)=32),
      journal BLOB NOT NULL CHECK(length(journal)=32)
    ) STRICT""",
    "snapshot": """CREATE TABLE snapshot (
      slot INTEGER PRIMARY KEY CHECK(slot=1),
      snapshot BLOB NOT NULL CHECK(length(snapshot)=32),
      epoch BLOB NOT NULL CHECK(length(epoch)=8),
      ids BLOB NOT NULL CHECK(length(ids)=32)
    ) STRICT""",
    "attempts": """CREATE TABLE attempts (
      nonce BLOB PRIMARY KEY CHECK(length(nonce)=32),
      binding BLOB NOT NULL,
      snapshot BLOB NOT NULL CHECK(length(snapshot)=32),
      epoch BLOB NOT NULL CHECK(length(epoch)=8),
      state TEXT NOT NULL CHECK(state IN ('reserved','rejected','authorized','dispatch_started','delivered','callback_failed')),
      authorized_once INTEGER NOT NULL DEFAULT 0 CHECK(authorized_once IN (0,1)),
      callback_once INTEGER NOT NULL DEFAULT 0 CHECK(callback_once IN (0,1) AND callback_once<=authorized_once),
      reply_hash BLOB CHECK(reply_hash IS NULL OR length(reply_hash)=32),
      frame_hash BLOB CHECK(frame_hash IS NULL OR length(frame_hash)=32),
      reason TEXT NOT NULL DEFAULT '',
      CHECK((state IN ('reserved','rejected') AND callback_once=0)
        OR (state='authorized' AND authorized_once=1 AND callback_once=0)
        OR (state IN ('dispatch_started','delivered','callback_failed') AND authorized_once=1 AND callback_once=1))
    ) STRICT""",
}


class LifecycleError(RuntimeError):
    """Trusted local lifecycle failure; never an HE/private error oracle."""


class ConsumedRequestError(LifecycleError):
    pass


class StaleSnapshotError(LifecycleError):
    pass


class CallbackFailed(LifecycleError):
    pass


@dataclass(frozen=True)
class Reservation:
    journal_id: bytes
    binding: auth.RequestBinding


@dataclass(frozen=True)
class LocalAuthorization:
    """Public local record, not a signed token or hardware attestation."""

    journal_id: bytes
    binding: auth.RequestBinding
    reply_hash: bytes
    frame: bytes


def _hash(value):
    return hashlib.sha256(value).digest()


def _epoch_bytes(value):
    return auth._epoch(value).to_bytes(8, "little")


def _binding_bytes(binding):
    if type(binding) is not auth.RequestBinding:
        raise ValueError("Wrong immutable request binding")
    fields = binding.fields()
    auth._epoch(fields[1])
    for at in (0, 2, 3, 4, 5):
        auth._fixed(fields[at], 32, "request binding")
    return auth._pack(fields)


def _ids_digest(enrollment):
    return _hash(b"".join(value.to_bytes(8, "little") for value in enrollment.metadata.ids))


class LocalJournal:
    """One process-owned handle to a shared trusted, non-rollback database.

    Connections/transactions are short lived; the SQLite write lock orders
    both threads and independent processes. The database is never held while
    native arithmetic or a callback runs. No abandoned attempt is retried.
    """

    def __init__(self, path, owner_public_key, policy_digest, scope_id):
        if str(path) == ":memory:":
            raise ValueError("A persistent local journal is required")
        self.path = Path(path).resolve()
        self._owner = auth._fixed(owner_public_key, 32, "owner key")
        self._policy = auth._fixed(policy_digest, 32, "policy digest")
        self._scope = auth._fixed(scope_id, 32, "index scope")
        self._code = _hash(Path(__file__).read_bytes())
        self._pid, self._closed = os.getpid(), False
        self._initialize()

    @property
    def journal_id(self):
        self._require()
        return self._journal_id

    def _require(self):
        # Check PID before SQLite, even if a parent thread held a database lock.
        if self._pid != os.getpid() or self._closed:
            raise LifecycleError("Closed or inherited local journal")

    def _connect(self):
        self._require()
        connection = None
        try:
            connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA trusted_schema=OFF")
            if connection.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
                raise LifecycleError("Wrong durable journal mode")
            return connection
        except sqlite3.Error as error:
            if connection is not None:
                connection.close()
            raise LifecycleError("Durable journal connection failed") from error
        except BaseException:
            if connection is not None:
                connection.close()
            raise

    def _validate(self, connection):
        if (
            connection.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID
            or connection.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION
        ):
            raise LifecycleError("Foreign local journal")
        definitions = {
            row["name"]: row["sql"]
            for row in connection.execute(
                "SELECT name,sql FROM sqlite_schema WHERE type IN ('table','view','trigger')"
            )
        }
        if definitions != _SCHEMA:
            raise LifecycleError("Wrong local journal schema")
        row = connection.execute("SELECT * FROM configuration WHERE slot=1").fetchone()
        if row is None or tuple(row) != (
            1,
            self._owner,
            self._policy,
            self._scope,
            self._code,
            self._journal_id,
        ):
            raise LifecycleError("Foreign owner/scope/policy journal")

    def _initialize(self):
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            definitions = connection.execute(
                "SELECT name FROM sqlite_schema WHERE type='table'"
            ).fetchall()
            if not definitions:
                if (
                    connection.execute("PRAGMA application_id").fetchone()[0] != 0
                    or connection.execute("PRAGMA user_version").fetchone()[0] != 0
                ):
                    raise LifecycleError("Foreign local database")
                for statement in _SCHEMA.values():
                    connection.execute(statement)
                connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                self._journal_id = secrets.token_bytes(32)
                connection.execute(
                    "INSERT INTO configuration VALUES(1,?,?,?,?,?)",
                    (self._owner, self._policy, self._scope, self._code, self._journal_id),
                )
            else:
                row = connection.execute(
                    "SELECT journal FROM configuration WHERE slot=1"
                ).fetchone()
                if row is None:
                    raise LifecycleError("Missing local journal identity")
                self._journal_id = auth._fixed(row[0], 32, "journal identity")
            self._validate(connection)
            connection.execute("COMMIT")
        except sqlite3.Error as error:
            raise LifecycleError("Durable journal initialization failed") from error
        finally:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            connection.close()

    @contextmanager
    def _transaction(self):
        connection = None
        try:
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            self._validate(connection)
            yield connection
            connection.execute("COMMIT")
        except sqlite3.Error as error:
            raise LifecycleError("Durable journal operation failed") from error
        finally:
            if connection is not None:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                connection.close()

    def _enrollment(self, enrollment):
        self._require()
        if type(enrollment) is not auth.OwnerEnrollment:
            raise ValueError("Authenticated owned enrollment required")
        enrollment._context._require_process()
        enrollment._context._require_open()
        if (
            enrollment._factory._owner_id != self._owner
            or enrollment._factory.policy_digest != self._policy
        ):
            raise ValueError("Foreign owner/policy enrollment")
        return enrollment.snapshot_id, _epoch_bytes(enrollment.epoch), _ids_digest(enrollment)

    def install(self, enrollment):
        """Trusted owner activation; idempotence does not permit epoch equivocation."""
        context = self._enrollment(enrollment)
        with self._transaction() as connection:
            current = connection.execute(
                "SELECT snapshot,epoch,ids FROM snapshot WHERE slot=1"
            ).fetchone()
            if current is not None:
                if tuple(current) == context:
                    return
                if enrollment.epoch <= int.from_bytes(current["epoch"], "little"):
                    raise StaleSnapshotError("Snapshot epoch cannot regress or equivocate")
            connection.execute("INSERT OR REPLACE INTO snapshot VALUES(1,?,?,?)", context)

    @staticmethod
    def _current(connection, binding):
        row = connection.execute("SELECT snapshot,epoch,ids FROM snapshot WHERE slot=1").fetchone()
        return row is not None and tuple(row) == (
            binding.snapshot_id,
            _epoch_bytes(binding.epoch),
            binding.ids_digest,
        )

    def reserve(self, enrollment, original_packet):
        """Authenticate/consume before seed parsing, preparation or admission."""
        self._enrollment(enrollment)
        width = enrollment.metadata.profile.n * native.COMMON_WIDTH
        payload = auth._verify(
            original_packet, enrollment._factory._anchor, auth.QUERY_TAG, width + 1024
        )
        fields = auth._unpack(payload, limit=width + 768, array_cap=5)
        if (
            type(fields) is not list
            or len(fields) != 5
            or auth._fixed(fields[0], 32, "snapshot ID") != enrollment.snapshot_id
            or auth._epoch(fields[1]) != enrollment.epoch
            or auth._fixed(fields[2], 32, "policy digest") != self._policy
            or type(fields[4]) is not bytes
        ):
            raise ValueError("Foreign signed request context")
        binding = auth.RequestBinding(
            enrollment.snapshot_id,
            enrollment.epoch,
            self._policy,
            _hash(auth.QUERY_TAG + self._owner + payload),
            auth._fixed(fields[3], 32, "request nonce"),
            _ids_digest(enrollment),
        )
        packed = _binding_bytes(binding)
        duplicate = False
        with self._transaction() as connection:
            current = self._current(connection, binding)
            try:
                connection.execute(
                    "INSERT INTO attempts(nonce,binding,snapshot,epoch,state,reason) VALUES(?,?,?,?,?,?)",
                    (
                        binding.nonce,
                        packed,
                        binding.snapshot_id,
                        _epoch_bytes(binding.epoch),
                        "reserved" if current else "rejected",
                        "" if current else "stale_at_reservation",
                    ),
                )
            except sqlite3.IntegrityError:
                duplicate = True
        # Raise after commit: a signed stale attempt must remain consumed.
        if duplicate:
            raise ConsumedRequestError("Request identity already consumed")
        if not current:
            raise StaleSnapshotError("Signed request snapshot is not current")
        return Reservation(self._journal_id, binding)

    def _row(self, connection, reservation):
        if type(reservation) is not Reservation or reservation.journal_id != self._journal_id:
            raise ValueError("Foreign immutable reservation")
        packed = _binding_bytes(reservation.binding)
        row = connection.execute(
            "SELECT * FROM attempts WHERE nonce=?", (reservation.binding.nonce,)
        ).fetchone()
        if row is None or row["binding"] != packed:
            raise LifecycleError("Unknown bound attempt")
        return row

    def _reject(self, reservation, reason):
        with self._transaction() as connection:
            row = self._row(connection, reservation)
            if row["state"] == "reserved":
                connection.execute(
                    "UPDATE attempts SET state='rejected',reason=? WHERE nonce=?",
                    (reason, reservation.binding.nonce),
                )

    def _authorize(self, reservation, reply_hash, frame):
        auth._fixed(reply_hash, 32, "complete reply hash")
        if type(frame) is not bytes or not frame or len(frame) > native.PACKET_CAP:
            raise ValueError("Wrong complete admitted frame")
        with self._transaction() as connection:
            row = self._row(connection, reservation)
            if row["state"] != "reserved" or row["authorized_once"]:
                raise ConsumedRequestError("Attempt cannot be authorized again")
            if not self._current(connection, reservation.binding):
                connection.execute(
                    "UPDATE attempts SET state='rejected',reason='stale_at_authorization' WHERE nonce=?",
                    (reservation.binding.nonce,),
                )
                return None
            connection.execute(
                "UPDATE attempts SET state='authorized',authorized_once=1,reply_hash=?,frame_hash=? WHERE nonce=?",
                (reply_hash, _hash(frame), reservation.binding.nonce),
            )
        return LocalAuthorization(self._journal_id, reservation.binding, reply_hash, frame)

    def _claim(self, authorization):
        self._require()
        if type(authorization) is not LocalAuthorization:
            raise ValueError("Bound local authorization required")
        auth._fixed(authorization.reply_hash, 32, "reply hash")
        if (
            type(authorization.frame) is not bytes
            or not authorization.frame
            or len(authorization.frame) > native.PACKET_CAP
        ):
            raise ValueError("Wrong immutable authorization frame")
        reservation = Reservation(authorization.journal_id, authorization.binding)
        stale = False
        with self._transaction() as connection:
            row = self._row(connection, reservation)
            if row["reply_hash"] != authorization.reply_hash or row["frame_hash"] != _hash(
                authorization.frame
            ):
                raise LifecycleError("Authorization/frame differs from admitted record")
            if row["state"] != "authorized" or row["callback_once"]:
                raise ConsumedRequestError("Callback identity already consumed")
            if not self._current(connection, authorization.binding):
                stale = True
                connection.execute(
                    "UPDATE attempts SET state='rejected',reason='stale_at_dispatch' WHERE nonce=?",
                    (authorization.binding.nonce,),
                )
            else:
                connection.execute(
                    "UPDATE attempts SET state='dispatch_started',callback_once=1 WHERE nonce=?",
                    (authorization.binding.nonce,),
                )
        if stale:
            raise StaleSnapshotError("Authorization snapshot is no longer current")
        return authorization.frame

    def _finish(self, authorization, failed):
        with self._transaction() as connection:
            row = self._row(
                connection, Reservation(authorization.journal_id, authorization.binding)
            )
            if row["state"] != "dispatch_started" or not row["callback_once"]:
                raise ConsumedRequestError("No live callback claim")
            connection.execute(
                "UPDATE attempts SET state=?,reason=? WHERE nonce=?",
                (
                    "callback_failed" if failed else "delivered",
                    "callback_failed" if failed else "",
                    authorization.binding.nonce,
                ),
            )

    def status(self, nonce):
        """Trusted diagnostic: public context/hashes only, never callback output."""
        auth._fixed(nonce, 32, "nonce")
        with self._transaction() as connection:
            row = connection.execute("SELECT * FROM attempts WHERE nonce=?", (nonce,)).fetchone()
            if row is None:
                return None
            result = dict(row)
            result["epoch"] = int.from_bytes(result["epoch"], "little")
            return result

    def summary(self):
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT count(*),coalesce(sum(authorized_once),0),coalesce(sum(callback_once),0) FROM attempts"
            ).fetchone()
            return {"attempts": row[0], "authorizations": row[1], "callback_claims": row[2]}

    def close(self):
        self._closed = True  # No persistent connection or inherited mutex to close.

    def __enter__(self):
        self._require()
        return self

    def __exit__(self, *_args):
        self.close()

    def __copy__(self):
        raise TypeError("Local journal ownership cannot be copied")

    def __deepcopy__(self, _memo):
        raise TypeError("Local journal ownership cannot be copied")

    def __reduce_ex__(self, _protocol):
        raise TypeError("Local journal ownership cannot be serialized")


class LocalAuthorizer:
    """Public checker/controller. No callback, producer or HE secret is used."""

    def __init__(self, journal):
        if type(journal) is not LocalJournal:
            raise ValueError("Explicit trusted local journal required")
        self.journal = journal

    def admit(self, enrollment, original_packet, reply_packet):
        reservation = self.journal.reserve(enrollment, original_packet)
        request = None
        try:
            request = enrollment.request(original_packet)
            if request.binding != reservation.binding:
                raise LifecycleError("Prepared request differs from consumed original")
            frame = request.checked_frame(reply_packet)
            if frame is None:
                self.journal._reject(reservation, "public_admission_rejected")
                return None
            return self.journal._authorize(reservation, _hash(reply_packet), frame)
        except BaseException:
            # Never reset a nonce. A journal failure may leave 'reserved',
            # which still blocks retries; no callback exists on this path.
            self.journal._reject(reservation, "preparation_or_admission_failed")
            raise
        finally:
            if request is not None:
                request.close()


class LocalReleaseGuard:
    """Trusted local hook seam; actual signed/attested client release is Q78."""

    def __init__(self, journal):
        if type(journal) is not LocalJournal:
            raise ValueError("Explicit trusted local journal required")
        self.journal = journal

    def deliver(self, authorization, callback):
        frame = self.journal._claim(authorization)  # Committed before any hook.
        failed = False
        try:
            callback(frame)  # Do not expose the hook's value through this API.
        except Exception:
            failed = True
        # Outside the exception handler, so journal errors do not attach the
        # hook's exception/message as context. Either failure stays consumed.
        try:
            self.journal._finish(authorization, failed)
        except Exception:
            # The prior claim is already durable. Missing completion recording
            # cannot license another hook or expose a private hook diagnostic.
            raise LifecycleError("Callback claim consumed; completion unavailable") from None
        if failed:
            raise CallbackFailed("Local callback failed; request stays consumed") from None
