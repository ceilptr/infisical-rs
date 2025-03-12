# infisical-rs (tentative until I can find a better non-conflicting crate name)
# problem
while windowshopping around recently for solutions to the infernal question of secrets management, i began looking into Infisical as a simpler alternative to trying to set up something like Hashicorp Vault. All this is fine and well except:
- the Infisical team currently does not have a Rustlang binding for their API (apparently this is currently being worked on internally, but the last mention I could find of this was a random Infisical forum post from 2023 or so)
- The sole result on crates.io was updated >2 years ago and has no support for the current service account infrastructure of Infisical (along with another semi-recently that only allows for retrieval of client secrets)
- searching across Github is much of the same, with the seemingly other sole Github repo being an enpty initial commit.

at best, one can't do any worse. Enter me, I suppose.

# tech stack
currently, infisical-rs runs on these major depenedencies to keep things light:
- reqwest,
- serde/serde-json
- secrecy (to ensure on-drop data/struct invalidation and generally limit access to sensitive client data)
# a multitude of things to keep in mind here:  
- this is _very_ early days for this API (<1 month in), and by extension is:
  - in **_very_** early alpha, and will be for quite a while
  - pretty much entirely unstable and unfit for production. Expect consistent breaking changes for the next long while.
- this is my first time having to roll out an API (and for that matter, my first on a lot of things such as robust application and API security)
- this is currently a very naive implementation of a few reqwest::Client calls and subsequent de/serialization of Rust structures and error handling. Feel free to yell at the clouds (or me, for that matter) in [github discussions](https://github.com/ceilptr/infisical-rs/discussions) if this takes off pasy anything ground-level.

# the immediate future
The plan is to: 
- continue building out the groundwork for the various return structs of the API,
- finish out the Universal Authorization and Secrets API endpoints first,
- move on to the other authorization types as much as my knowledge allows (which considering this is my first time having to deal with GCP/AWS/Azure, this may be a bit of stretch out the gate)
  - I would be entirely out of my knowledge check with Kubernetes Auth, and would either have to figure out k8s on my own time, or rely on community contributions.
- implement endpoints such as `/folder`, `/projects`, etc.

# another note
fundamentally, there is nothing crazy going on in this library
