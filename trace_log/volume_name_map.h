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

#ifndef __VOLUME_NAME_MAP_H__
#define __VOLUME_NAME_MAP_H__

#define INVALID_INDEX 0xffffffff

#define MAX_DRIVE_SIGN_NUM ( ULONG )( 'Z' - 'A' + 1 )
#define MAX_VOLUME_COUNT 64
#define INVALID_DRIVE_INDEX ( ULONG )( -1 )
#define ALL_DRIVE_INDEX ( ULONG )( 0xffffffff )

#ifndef MAX_DOS_VOLUME_NAME_LEN 
#define MAX_DOS_VOLUME_NAME_LEN 32
#endif //MAX_DOS_VOLUME_NAME_LEN 

#ifndef MAX_NATIVE_VOLUME_NAME_LEN 
#define MAX_NATIVE_VOLUME_NAME_LEN 256
#endif //MAX_NATIVE_VOLUME_NAME_LEN 

typedef struct _volume_name_map
{
	WCHAR dev_name[ MAX_NATIVE_VOLUME_NAME_LEN + 1 ]; 
	ULONG dev_name_len; 
	WCHAR dos_name[ MAX_DOS_VOLUME_NAME_LEN + 1 ]; 
	ULONG dos_name_len; 
} volume_name_map, *pvolume_name_map; 

extern volume_name_map all_volumes_name_map[ MAX_VOLUME_COUNT ]; 

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

#ifndef _DRIVER 
	LRESULT get_volume_dos_name( __in PWCHAR vol_name, 
		__out PWCHAR dos_name_out, 
		__in ULONG buf_len ); 


	LRESULT update_volume_name_map( ULONG drv_mask, ULONG flags ); 

	LRESULT init_volumes_name_map(); 

	HRESULT init_volumes_name_map_ex(); 


#endif //_DRIVER

INLINE ULONG get_volume_map_index( LPCWSTR dos_name )
{
	ULONG index = INVALID_INDEX; 

	ASSERT( dos_name != NULL ); 

	do 
	{
		if( dos_name[ 0 ] >= 'a' 
			&& dos_name[ 0 ] <= 'z' )
		{
			index = dos_name[ 0 ] - L'a'; 
		}
		else if( dos_name[ 0 ] >= 'A' 
			|| dos_name[ 0 ] <= 'Z' ) 
		{
			index = dos_name[ 0 ] - L'A'; 
		}
		else
		{
			log_trace( ( MSG_ERROR, "invalid dos name of volume %ws\n", dos_name ) ); 
		}
	} while( FALSE );

	return index; 
}

#define ONLY_UPDATE_NO_SET_VOL_MAP 0x00000001

LRESULT input_volume_map_name( LPCWSTR dos_name, ULONG dos_name_len, LPCWSTR dev_name, ULONG dev_name_len, ULONG flags ); 

LRESULT convert_native_path_to_dos( LPWSTR native_path, ULONG native_path_len, LPWSTR dos_path, ULONG ccb_buf_len, ULONG *ccb_ret_len ); 

LRESULT input_vol_map_from_dev_name( LPCWSTR native_path, ULONG native_path_len ); 

INLINE LRESULT _convert_native_path_to_dos( LPCWSTR native_path, ULONG native_path_len, LPWSTR dos_path, ULONG ccb_buf_len, ULONG *ccb_ret_len )
{
	LRESULT ret = ERROR_SUCCESS; 

	do 
	{
		ret = convert_native_path_to_dos( ( LPWSTR )native_path, native_path_len, dos_path, ccb_buf_len, ccb_ret_len ); 

		if( ret != ERROR_NOT_FOUND )
		{
			ret = input_vol_map_from_dev_name( native_path, native_path_len ); 

			if( ret != ERROR_SUCCESS )
			{
				break; 
			}

			ret = convert_native_path_to_dos( ( LPWSTR )native_path, native_path_len, dos_path, ccb_buf_len, ccb_ret_len ); 
		}
	} while ( FALSE );

	return ret; 
}


LRESULT convert_dos_path_to_native( LPCWSTR dos_path, ULONG dos_path_len, LPWSTR native_path, ULONG ccb_buf_len, ULONG *ccb_ret_len ); 

LRESULT input_vol_map_from_dos_name( LPCWSTR dos_path, ULONG dos_path_len ); 

INLINE LRESULT _convert_dos_path_to_native( LPCWSTR dos_path, ULONG dos_path_len, LPWSTR native_path, ULONG ccb_buf_len, ULONG *ccb_ret_len )
{
	LRESULT ret = ERROR_SUCCESS; 

	do 
	{
		ret = convert_dos_path_to_native( dos_path, dos_path_len, native_path, ccb_buf_len, ccb_ret_len ); 

		if( ret != ERROR_NOT_FOUND )
		{
			ret = input_vol_map_from_dos_name( dos_path, dos_path_len ); 

			if( ret != ERROR_SUCCESS )
			{
				break; 
			}

			ret = convert_dos_path_to_native( dos_path, dos_path_len, native_path, ccb_buf_len, ccb_ret_len ); 
		}
	} while ( FALSE );

	return ret; 
}

ULONG first_drive_index_from_mask( ULONG unitmask ); 

INLINE WCHAR first_drive_from_mask( ULONG unitmask )
{
	ULONG i;
	WCHAR drive_sign = L' '; 

	do 
	{
		i = first_drive_index_from_mask( unitmask ); 

		if( i == INVALID_DRIVE_INDEX )
		{
			break; 
		}

		drive_sign = ( WCHAR )i + L'A'; 

	} while ( FALSE );

	return drive_sign; 
}

INLINE LRESULT _input_volume_map_name( volume_name_map *path_map )
{
	LRESULT ret = ERROR_SUCCESS; 

	do 
	{
		if( path_map == NULL )
		{
			ret = ERROR_INVALID_PARAMETER; 
			break; 
		}

		if( path_map->dev_name_len > ARRAYSIZE( path_map->dev_name ) - 1 )
		{
			ret = ERROR_INVALID_PARAMETER; 
			break; 
		}

		if( path_map->dos_name_len > ARRAYSIZE( path_map->dos_name ) - 1 )
		{
			ret = ERROR_INVALID_PARAMETER; 
			break; 
		}

		if( path_map->dev_name[ path_map->dev_name_len ] != L'\0' )
		{
			ret = ERROR_INVALID_PARAMETER; 
			break; 
		}

		if( path_map->dos_name[ path_map->dos_name_len ] != L'\0' )
		{
			ret = ERROR_INVALID_PARAMETER; 
			break; 
		}

		ret = input_volume_map_name( path_map->dos_name, 
			path_map->dos_name_len, 
			path_map->dev_name, 
			path_map->dev_name_len, 
			0 ); 
	}while( FALSE );

	return ret; 
}

INLINE LRESULT _remove_volume_map_name( volume_name_map *path_map )
{
	LRESULT ret = ERROR_SUCCESS; 

	do 
	{
		if( path_map == NULL )
		{
			ret = ERROR_INVALID_PARAMETER; 
			break; 
		}

		if( path_map->dev_name_len > ARRAYSIZE( path_map->dev_name ) - 1 )
		{
			ret = ERROR_INVALID_PARAMETER; 
			break; 
		}

		if( path_map->dos_name_len > ARRAYSIZE( path_map->dos_name ) - 1 )
		{
			ret = ERROR_INVALID_PARAMETER; 
			break; 
		}

		if( path_map->dev_name[ path_map->dev_name_len ] != L'\0' )
		{
			ret = ERROR_INVALID_PARAMETER; 
			break; 
		}

		if( path_map->dos_name[ path_map->dos_name_len ] != L'\0' )
		{
			ret = ERROR_INVALID_PARAMETER; 
			break; 
		}

		if( path_map->dev_name_len != 0 
			|| path_map->dev_name[ 0 ] != L'\0' )
		{
			path_map->dev_name_len = 0; 
			path_map->dev_name[ 0 ] = L'\0'; 
		}

		ret = input_volume_map_name( path_map->dos_name, 
			path_map->dos_name_len, 
			path_map->dev_name, 
			path_map->dev_name_len, 
			0 ); 
	}while( FALSE );

	return ret; 
}

#ifdef __cplusplus
}
#endif //__cplusplus

#endif //__VOLUME_NAME_MAP_H__