#[cfg(test)]
mod tests {
    use anyhow::Result;
    use curv::{arithmetic::Converter, BigInt};
    use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::{
        party_i::verify,
        state_machine::{
            keygen::Keygen,
            sign::{OfflineStage, SignManual},
        },
    };
    use round_based::StateMachine;

    #[test]
    fn sign() -> Result<()> {
        let mut c1 = Keygen::new(1, 1, 3)?;
        let mut c2 = Keygen::new(2, 1, 3)?;
        let mut c3 = Keygen::new(3, 1, 3)?;

        assert!(c1.wants_to_proceed());
        assert!(c2.wants_to_proceed());
        assert!(c3.wants_to_proceed());

        assert!(c1.message_queue().is_empty());
        assert!(c2.message_queue().is_empty());
        assert!(c3.message_queue().is_empty());

        let c1_r1: Vec<_> = {
            c1.proceed()?;
            c1.message_queue().drain(..).collect()
        };
        assert!(!c1_r1.is_empty());

        let c2_r1: Vec<_> = {
            c2.proceed()?;
            c2.message_queue().drain(..).collect()
        };
        assert!(!c2_r1.is_empty());

        let c3_r1: Vec<_> = {
            c3.proceed()?;
            c3.message_queue().drain(..).collect()
        };
        assert!(!c3_r1.is_empty());

        assert_eq!(1, c1.current_round());
        assert_eq!(1, c2.current_round());
        assert_eq!(1, c3.current_round());

        // Feed incoming messages to client 1 for round 1
        for m in c2_r1.iter().chain(c3_r1.iter()) {
            c1.handle_incoming(m.clone())?;
        }
        //assert!(c1.wants_to_proceed());

        // Feed incoming messages to client 2 for round 1
        for m in c1_r1.iter().chain(c3_r1.iter()) {
            c2.handle_incoming(m.clone())?;
        }
        //assert!(c2.wants_to_proceed());

        // Feed incoming messages to client 3 for round 1
        for m in c1_r1.iter().chain(c2_r1.iter()) {
            c3.handle_incoming(m.clone())?;
        }
        //assert!(c3.wants_to_proceed());

        let c1_r2: Vec<_> = {
            c1.proceed()?;
            c1.message_queue().drain(..).collect()
        };
        assert!(!c1_r2.is_empty());

        let c2_r2: Vec<_> = {
            c2.proceed()?;
            c2.message_queue().drain(..).collect()
        };
        assert!(!c2_r2.is_empty());

        let c3_r2: Vec<_> = {
            c3.proceed()?;
            c3.message_queue().drain(..).collect()
        };
        assert!(!c3_r2.is_empty());

        assert_eq!(2, c1.current_round());
        assert_eq!(2, c2.current_round());
        assert_eq!(2, c3.current_round());

        // Feed incoming messages to client 1 for round 2
        for m in c2_r2.iter().chain(c3_r2.iter()) {
            c1.handle_incoming(m.clone())?;
        }

        // Feed incoming messages to client 2 for round 2
        for m in c1_r2.iter().chain(c3_r2.iter()) {
            c2.handle_incoming(m.clone())?;
        }

        // Feed incoming messages to client 3 for round 2
        for m in c1_r2.iter().chain(c2_r2.iter()) {
            c3.handle_incoming(m.clone())?;
        }

        let c1_r3: Vec<_> = {
            c1.proceed()?;
            c1.message_queue().drain(..).collect()
        };
        assert!(!c1_r3.is_empty());

        let c2_r3: Vec<_> = {
            c2.proceed()?;
            c2.message_queue().drain(..).collect()
        };
        assert!(!c2_r3.is_empty());

        let c3_r3: Vec<_> = {
            c3.proceed()?;
            c3.message_queue().drain(..).collect()
        };
        assert!(!c3_r3.is_empty());

        assert_eq!(3, c1.current_round());
        assert_eq!(3, c2.current_round());
        assert_eq!(3, c3.current_round());

        // Handle round 3 as p2p
        for m in c1_r3.iter().chain(c2_r3.iter()).chain(c3_r3.iter()) {
            if let Some(receiver) = &m.receiver {
                match receiver {
                    1 => c1.handle_incoming(m.clone())?,
                    2 => c2.handle_incoming(m.clone())?,
                    3 => c3.handle_incoming(m.clone())?,
                    _ => panic!("unknown party index (keygen)"),
                }
            }
        }

        let c1_r4: Vec<_> = {
            c1.proceed()?;
            c1.message_queue().drain(..).collect()
        };
        assert!(!c1_r4.is_empty());

        let c2_r4: Vec<_> = {
            c2.proceed()?;
            c2.message_queue().drain(..).collect()
        };
        assert!(!c2_r4.is_empty());

        let c3_r4: Vec<_> = {
            c3.proceed()?;
            c3.message_queue().drain(..).collect()
        };
        assert!(!c3_r4.is_empty());

        assert_eq!(4, c1.current_round());
        assert_eq!(4, c2.current_round());
        assert_eq!(4, c3.current_round());

        // Feed incoming messages to client 1 for round 4
        for m in c2_r4.iter().chain(c3_r4.iter()) {
            c1.handle_incoming(m.clone())?;
        }

        // Feed incoming messages to client 2 for round 4
        for m in c1_r4.iter().chain(c3_r4.iter()) {
            c2.handle_incoming(m.clone())?;
        }

        // Feed incoming messages to client 3 for round 4
        for m in c1_r4.iter().chain(c2_r4.iter()) {
            c3.handle_incoming(m.clone())?;
        }

        c1.proceed()?;
        c2.proceed()?;
        c3.proceed()?;

        assert_eq!(5, c1.current_round());
        assert_eq!(5, c2.current_round());
        assert_eq!(5, c3.current_round());

        assert!(c1.is_finished());
        assert!(c2.is_finished());
        assert!(c3.is_finished());

        let ks1 = c1.pick_output().unwrap()?;
        let ks2 = c2.pick_output().unwrap()?;
        let ks3 = c3.pick_output().unwrap()?;

        let pk1 = ks1.public_key();
        let pk2 = ks2.public_key();
        let pk3 = ks3.public_key();

        assert_eq!(65, pk1.to_bytes(false).len());
        assert_eq!(65, pk2.to_bytes(false).len());
        assert_eq!(65, pk3.to_bytes(false).len());

        // Start signing offline stage
        let mut s1 = OfflineStage::new(1, vec![3, 2], ks3)?;
        let mut s2 = OfflineStage::new(2, vec![3, 2], ks2)?;

        assert!(s1.wants_to_proceed());
        assert!(s2.wants_to_proceed());

        let s1_r1: Vec<_> = {
            s1.proceed()?;
            s1.message_queue().drain(..).collect()
        };
        assert!(!s1_r1.is_empty());

        let s2_r1: Vec<_> = {
            s2.proceed()?;
            s2.message_queue().drain(..).collect()
        };
        assert!(!s2_r1.is_empty());

        assert_eq!(1, s1.current_round());
        assert_eq!(1, s2.current_round());

        // Feed incoming messages to signer 1 for round 1
        for m in s2_r1.iter() {
            s1.handle_incoming(m.clone())?;
        }

        // Feed incoming messages to signer 2 for round 1
        for m in s1_r1.iter() {
            s2.handle_incoming(m.clone())?;
        }

        assert!(s1.wants_to_proceed());
        assert!(s2.wants_to_proceed());

        let s1_r2: Vec<_> = {
            s1.proceed()?;
            s1.message_queue().drain(..).collect()
        };
        assert!(!s1_r2.is_empty());

        let s2_r2: Vec<_> = {
            s2.proceed()?;
            s2.message_queue().drain(..).collect()
        };
        assert!(!s2_r2.is_empty());

        assert_eq!(2, s1.current_round());
        assert_eq!(2, s2.current_round());

        // Handle round 2 as p2p
        for m in s1_r2.iter().chain(s2_r2.iter()) {
            if let Some(receiver) = &m.receiver {
                match receiver {
                    1 => s1.handle_incoming(m.clone())?,
                    2 => s2.handle_incoming(m.clone())?,
                    _ => panic!("unknown party index (sign)"),
                }
            }
        }

        assert!(s1.wants_to_proceed());
        assert!(s2.wants_to_proceed());

        let s1_r3: Vec<_> = {
            s1.proceed()?;
            s1.message_queue().drain(..).collect()
        };
        assert!(!s1_r3.is_empty());

        let s2_r3: Vec<_> = {
            s2.proceed()?;
            s2.message_queue().drain(..).collect()
        };
        assert!(!s2_r3.is_empty());

        assert_eq!(3, s1.current_round());
        assert_eq!(3, s2.current_round());

        // Feed incoming messages to signer 1 for round 3
        for m in s2_r3.iter() {
            s1.handle_incoming(m.clone())?;
        }

        // Feed incoming messages to signer 2 for round 3
        for m in s1_r3.iter() {
            s2.handle_incoming(m.clone())?;
        }

        assert!(s1.wants_to_proceed());
        assert!(s2.wants_to_proceed());

        let s1_r4: Vec<_> = {
            s1.proceed()?;
            s1.message_queue().drain(..).collect()
        };
        assert!(!s1_r4.is_empty());

        let s2_r4: Vec<_> = {
            s2.proceed()?;
            s2.message_queue().drain(..).collect()
        };
        assert!(!s2_r4.is_empty());

        assert_eq!(4, s1.current_round());
        assert_eq!(4, s2.current_round());

        // Feed incoming messages to signer 1 for round 4
        for m in s2_r4.iter() {
            s1.handle_incoming(m.clone())?;
        }

        // Feed incoming messages to signer 2 for round 4
        for m in s1_r4.iter() {
            s2.handle_incoming(m.clone())?;
        }

        assert!(s1.wants_to_proceed());
        assert!(s2.wants_to_proceed());

        let s1_r5: Vec<_> = {
            s1.proceed()?;
            s1.message_queue().drain(..).collect()
        };
        assert!(!s1_r5.is_empty());

        let s2_r5: Vec<_> = {
            s2.proceed()?;
            s2.message_queue().drain(..).collect()
        };
        assert!(!s2_r5.is_empty());

        assert_eq!(5, s1.current_round());
        assert_eq!(5, s2.current_round());

        // Feed incoming messages to signer 1 for round 5
        for m in s2_r5.iter() {
            s1.handle_incoming(m.clone())?;
        }

        // Feed incoming messages to signer 2 for round 5
        for m in s1_r5.iter() {
            s2.handle_incoming(m.clone())?;
        }

        assert!(s1.wants_to_proceed());
        assert!(s2.wants_to_proceed());

        let s1_r6: Vec<_> = {
            s1.proceed()?;
            s1.message_queue().drain(..).collect()
        };
        assert!(!s1_r6.is_empty());

        let s2_r6: Vec<_> = {
            s2.proceed()?;
            s2.message_queue().drain(..).collect()
        };
        assert!(!s2_r6.is_empty());

        assert_eq!(6, s1.current_round());
        assert_eq!(6, s2.current_round());

        // Feed incoming messages to signer 1 for round 6
        for m in s2_r6.iter() {
            s1.handle_incoming(m.clone())?;
        }

        // Feed incoming messages to signer 2 for round 6
        for m in s1_r6.iter() {
            s2.handle_incoming(m.clone())?;
        }

        assert!(s1.wants_to_proceed());
        assert!(s2.wants_to_proceed());

        s1.proceed()?;
        s2.proceed()?;

        assert!(s1.is_finished());
        assert!(s2.is_finished());

        let s1_completed = s1.pick_output().unwrap()?;
        let s2_completed = s2.pick_output().unwrap()?;

        let s1_pk = s1_completed.public_key().clone();
        let s2_pk = s2_completed.public_key().clone();

        let data = BigInt::from_bytes(b"a message");

        // Sign the message
        let (sign1, partial1) = SignManual::new(data.clone(), s1_completed)?;
        let (sign2, partial2) = SignManual::new(data.clone(), s2_completed)?;

        // In the real world we need to broadcast and
        // wait for the partial signatures

        let sigs1 = vec![partial2];
        let sigs2 = vec![partial1];

        let signature1 = sign1.complete(&sigs1)?;
        let signature2 = sign2.complete(&sigs2)?;

        assert!(verify(&signature1, &s1_pk, &data).is_ok());
        assert!(verify(&signature2, &s2_pk, &data).is_ok());

        Ok(())
    }
}
