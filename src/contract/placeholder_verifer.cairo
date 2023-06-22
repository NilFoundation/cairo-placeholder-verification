#[contract]
mod PlaceholderVerifier {
    // Calls a function defined in outside module
    #[view]
    fn verify() -> bool {
       true
    }
}
