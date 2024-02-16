/*
 * Copyright 2010-2024 JiJie.Shi.
 *
 * This file is part of bittrace.
 * Licensed under the Gangoo License, Version 1.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef _DRIVER
#include "common.h"
#else
#include "common_func.h"
#endif //_DRIVER

#include "wild_card.h"

typedef enum _compare_state
{
	COMPARE_NORMAL, 
	COMPARE_ATERISK, 
	MAX_COMPARE_STATE, 
} compare_state, *pcompare_state; 

INT32 wild_card_compare( LPCWSTR str_src, ULONG str_src_len, LPCWSTR pattern, ULONG pattern_len )
{
	INT32 ret = 0; 
	INT32 i;
	INT32 pattern_index = 0; 
	INT32 next_aterisk_index = 0; 
	INT32 pattern_compare_index = 0; 
	compare_state cur_compare_state = COMPARE_NORMAL; 
	ULONG asterisk_tail_len; 

	for( i = 0, pattern_index = 0; ( ( ULONG )i < str_src_len ) && ( ( ULONG )pattern_index < pattern_len ); i ++ )
	{

#ifdef DBG
		if( ( ULONG )i >= pattern_len )
		{
			//__asm int 3; 
		}
#endif //DBG

		if( pattern[ pattern_index ] == ASTERISK_WILD_CARD )
		{
			INT32 j; 

			//cur_compare_state = COMPARE_ATERISK; 

			next_aterisk_index = -1; 
			for( j = pattern_index + 1; ( ULONG )j < pattern_len; j ++ )
			{
				if( pattern[ j ] == ASTERISK_WILD_CARD )
				{
					next_aterisk_index = j; 
					break; 
				}
			}

			if( next_aterisk_index == -1 )
			{
				pattern_compare_index = pattern_index + 1; 
				asterisk_tail_len = pattern_len - pattern_compare_index; 
				if( asterisk_tail_len == 0 )
				{
					pattern_index ++; 
					break; 
				}

				i = str_src_len - asterisk_tail_len; 
				pattern_index ++; 
			}
			else
			{
				ret = -1; 
				dbg_print( MSG_ERROR, "don't support multi-aterisk pattern compare %ws\n", pattern ); 
				break; 
			}
		}

		if( str_src[ i ] == L'\0' || pattern[ pattern_index ] == L'\0' )
		{
			break; 
		}

		if( pattern[ pattern_index ] != str_src[ i ] )
		{
#define IS_UPPER_CASE( ch ) ( L'A' <= ( ch ) && L'Z' >= ( ch ) )
#define IS_LOWER_CASE( ch ) ( L'a' <= ( ch ) && L'z' >= ( ch ) )
#define TO_UPPER( ch ) ( ( ch ) + ( L'A' - L'a' ) )

			if( ( IS_UPPER_CASE( pattern[ pattern_index ] ) && IS_LOWER_CASE( str_src[ i ] ) ) )
			{
				if( pattern[ pattern_index ] != TO_UPPER( str_src[ i ] ) )
				{
					ret = -i; 
					break; 
				}
			}
			else if( ( IS_UPPER_CASE( str_src[ i ] ) && IS_LOWER_CASE( pattern[ pattern_index ] ) ) )
			{
				if(  str_src[ i ] != TO_UPPER( pattern[ pattern_index ] ) )
				{
					ret = -i; 
					break; 
				}
			}
			else 
			{
				ret = -i; 
				break; 
			}
		}

		pattern_index ++;
		if( ret != 0 )
		{
			break; 
		}
	}

	if( ret == 0 )
	{
		if( ( i != str_src_len && str_src[ i ] != L'\0' ) 
			|| ( pattern_index != pattern_len && pattern[ pattern_index ] != L'\0' ) )
		{
			DBG_BP(); 
			ret = -i; 
		}
	}

	return ret; 
}