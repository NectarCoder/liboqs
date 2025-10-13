// Put symbols in namespace for use in a library.
// Only used by the liboqs integration

#ifndef LESS_NAMESPACE_H
#define LESS_NAMESPACE_H

#define LESS_NAMESPACE(f) _less_400_220_opt_##f

#define LESS_keygen LESS_NAMESPACE(LESS_keygen)
#define LESS_sign LESS_NAMESPACE(LESS_sign)
#define LESS_verify LESS_NAMESPACE(LESS_verify)
#define generate_keys LESS_NAMESPACE(generate_keys)
#define sign_digest LESS_NAMESPACE(sign_digest)
#define verify_signture LESS_NAMESPACE(verify_signture)

#endif