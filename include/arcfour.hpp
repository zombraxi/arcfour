#include <cstdint>

#ifdef _MSC_VER
#define ARCFOUR_FORCE_INLINE __forceinline
#elif defined(__GNUC__)
#define ARCFOUR_FORCE_INLINE __attribute__((always_inline)) inline
#else
#define ARCFOUR_FORCE_INLINE inline
#endif

#define ARCFOUR_CRYPT( data , data_len , key , key_len ) ::zbx::arcfour::crypt( data , data_len , key , key_len )

namespace zbx
{
	namespace arcfour
	{
	    namespace detail
	    {
		struct internal_state_t
		{
		    std::uint8_t Permutation[256];
		};

		ARCFOUR_FORCE_INLINE void schedule_key(internal_state_t& state, const std::uint8_t* key, const std::size_t key_length)
		{
		    std::size_t i;
		    std::size_t j;

		    for (i = 0; i < sizeof(internal_state_t::Permutation); i++)
		    {
		        state.Permutation[i] = i & 0xff;
		    }

		    j = 0;
		    for (i = 0; i < sizeof(internal_state_t::Permutation); i++)
		    {
		        j = (j + state.Permutation[i] + key[i % key_length]) & 0xff;

		        std::uint8_t ValAtPtrI = state.Permutation[i];
		        std::uint8_t ValAtPtrJ = state.Permutation[j];
		        state.Permutation[i] = ValAtPtrJ;
		        state.Permutation[j] = ValAtPtrI;
		    }
		}

		ARCFOUR_FORCE_INLINE void prga(internal_state_t& state, std::uint8_t* data, const std::size_t data_length)
		{

		    std::size_t i = 0;
		    std::size_t j = 0;

		    for (std::size_t ctr = 0; ctr < data_length; ctr++)
		    {
		        i = (i + 1) & 0xff;
		        j = (j + state.Permutation[i]) & 0xff;

		        std::uint8_t ValAtPtrI = state.Permutation[i];
		        std::uint8_t ValAtPtrJ = state.Permutation[j];
		        state.Permutation[i] = ValAtPtrJ;
		        state.Permutation[j] = ValAtPtrI;

		        std::size_t KeyStream = state.Permutation[(state.Permutation[i] + state.Permutation[j]) & 0xff];
		        std::uint8_t KeyStream8 = KeyStream & 0xff;

		        data[ctr] ^= KeyStream8;
		    }
		}
	    }

	    ARCFOUR_FORCE_INLINE void crypt(std::uint8_t* data, const std::size_t data_length, 
		                const std::uint8_t* key, const std::size_t key_length)
	    {
		detail::internal_state_t state;
		detail::schedule_key(state, key, key_length);
		detail::prga(state, data, data_length);
	    }
	}
}


