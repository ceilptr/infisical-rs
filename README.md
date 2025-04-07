# infisical-rs (tentative until I can find a better non-conflicting crate name)

## problem

while windowshopping around recently for solutions to the infernal question of secrets management, i began looking into Infisical as a simpler alternative to trying to set up something like Hashicorp Vault. All this is fine and well except:

- the Infisical team currently does not have a publicly available Rustlang binding for their API (apparently this is currently being worked on internally, but the last mention I could find of this was a random Infisical forum post from 2023 or so)
- The sole result on crates.io was updated >2 years ago and has no support for the current service account infrastructure of Infisical (along with another semi-recently that only allows for retrieval of client secrets)
- searching across Github is much of the same, with the seemingly other sole Github repo being an enpty initial commit.

at best, one can't do any worse. Enter me, I suppose.

## tech stack

currently, infisical-rs runs on these major dependencies to keep things light:

- reqwest,
- serde/serde-json
- secrecy (to ensure on-drop data/struct invalidation and generally limit access to sensitive client data)

tentatively planned crate features include:

- \[logging\] : (and the ability to control the verboseness and chirpiness of it)
- \[blocking\] : forcing the lib to use request::Blocking::client instead of the default unblocking client

## a multitude of things to keep in mind here  

- this is _very_ early days for this API (<1 month in), and by extension is:
  - in **_very_** early alpha, and will be for quite a while
  - pretty much entirely unstable and unfit for production. Expect consistent breaking changes for the next long while.
- this is my first time rolling out an API binding to this degree (and for that matter, my first on a lot of things such as robust application and API security)
- this is also my first time officially rolling out a Rust library, and leans towards educational rather than production-practical (for the moment, who knows what the future holds!)
- this is currently a very naive implementation consisting of a few reqwest::Client calls and subsequent de/serialization of Rust structures and error handling. Feel free to yell at the clouds (or me, for that matter) in [github discussions](https://github.com/ceilptr/infisical-rs/discussions) if this takes off past anything ground-level for improvements and suggestions.
- for the time-being the reqwest client type will be async, with blocking likely to come later down the line:
  - i'm currently assuming it would be more useful to call async reqwest and use something like block_on in sync/threaded code, rather than the other way around
  - the blocking code would be more or less a duplicate of the async functionality, so we might as well iron one out fully first
- i have not personally self-hosted an Infisical instance as of this writing. I can't particularly think of any major differences for this binding past changing the host url accessed in a method, but obviously YMMV.
  
## the immediate future

the plan is to:

- continue building out the groundwork for the various return structs of the API,
- finish out the Universal Authorization and Secrets API endpoints first,
- move on to the other authorization types as much as my knowledge allows (which considering this is my first time having to deal with GCP/AWS/Azure, this may be a bit of stretch out the gate)
  - I would be entirely out of my knowledge bounds with Kubernetes Auth, and would either have to figure out k8s on my own time, or rely on community contributions for this endpoint.
- implement endpoints such as `/folder`, `/projects`, etc, since they overall seem to be less work to implement.

## additional notes

- depending on how far my Google-Fu goes, implementation tracking will (most likely) be handled over on [this taiga project repo](https://tree.taiga.io/project/ceilptr-infisical-rs/timeline) or on Github Projects.
- I'm still figuring out how best to deal with crate testing, given testing with environment variables will likely be dodgy given their shared nature and the fact that Rust apparently runs its tests in parallel. For the moment a test_env.rs file with a series of static strings + LazyLocks to fight those nasty race conditions, and will likely the user to do the same if they wish to run test themselves.
