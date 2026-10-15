# Compile-fail doctests for the opaque `ApprovalReply`

Included into the crate docs under `cfg(doctest)` (see `src/lib.rs`). Every block below must **fail to compile**;
this is what makes "allow can only be created through `ApprovalReply::allow(ApplyProof)`" a type-level fact
(docs/testing-and-ci.md, security.md I5).

(a) The inner enum cannot be named or built from outside the crate.

```compile_fail
use agentnest_adapter_api::ApprovalReply;
let _reply = ApprovalReply(Inner::Allow);
```

```compile_fail
let _reply = agentnest_adapter_api::ApprovalReply(agentnest_adapter_api::Inner::Allow);
```

(a2) The private field cannot be destructured or constructed, so no allow can be forged through the tuple struct.

```compile_fail
use agentnest_adapter_api::ApprovalReply;
let reply = ApprovalReply::deny(String::new(), false);
let ApprovalReply(_inner) = reply;
```

(b) `allow` needs a proof.

```compile_fail
use agentnest_adapter_api::ApprovalReply;
let _reply = ApprovalReply::allow();
```

```compile_fail
use agentnest_adapter_api::ApprovalReply;
let _reply = ApprovalReply::allow(());
```

(c) The proof cannot be written as a literal.

```compile_fail
use agentnest_adapter_api::{ApplyProof, ApprovalReply};
let proof = ApplyProof(());
let _reply = ApprovalReply::allow(proof);
```

(d) One proof buys one allow (`ApplyProof` is neither `Clone` nor `Copy`).

```compile_fail
use agentnest_adapter_api::{ApplyProof, ApprovalReply};
let proof = ApplyProof::mint();
let _a = ApprovalReply::allow(proof);
let _b = ApprovalReply::allow(proof);
```

```compile_fail
use agentnest_adapter_api::ApplyProof;
fn needs_clone<T: Clone>() {}
needs_clone::<ApplyProof>();
```

(e) The wire view cannot be turned back into a reply, and a reply cannot be conjured from defaults or from data.

```compile_fail
use agentnest_adapter_api::{ApprovalReply, ReplyKind};
let _reply: ApprovalReply = ReplyKind::Allow.into();
```

```compile_fail
use agentnest_adapter_api::ApprovalReply;
let _reply = ApprovalReply::default();
```

```compile_fail
use agentnest_adapter_api::ApprovalReply;
fn needs_deserialize<T: serde::de::DeserializeOwned>() {}
needs_deserialize::<ApprovalReply>();
```

(f) There is no public "allow" shortcut in the default (non-`test-util`) build.

```compile_fail
#[cfg(feature = "test-util")]
compile_error!("only meaningful without the test-util feature");
let _reply = agentnest_adapter_api::ApprovalReply::allow_for_test();
```

```compile_fail
#[cfg(feature = "test-util")]
compile_error!("only meaningful without the test-util feature");
let _proof = agentnest_adapter_api::ApplyProof::mint_for_test();
```

The deny path and the read-only view do compile:

```
use agentnest_adapter_api::{ApprovalReply, ReplyKind};
let reply = ApprovalReply::deny("no".to_owned(), true);
assert_eq!(reply.as_wire(), ReplyKind::Deny { message: "no", interrupt: true });
```
