#ifndef VEOS_VE3_AMM_VEHVA_MGMT_VE3_H
#define VEOS_VE3_AMM_VEHVA_MGMT_VE3_H
#include <libved.h>
#include <ve_hw.h>
#define VESHM_END_ENTRY (VE3_DMAATB_ENTRY_MAX_SIZE * VE3_DMAATB_DIR_NUM)

#define VEHVA_4K_START          0x000000000000  /*!< Start of 4K region*/
#define VEHVA_4K_END            0x00000fffffff  /*!< End of 4K region*/
#define VEHVA_2M_START          0x008000000000  /*!< Start of 2M region*/
#define VEHVA_2M_END            0x009fffffffff  /*!< End of 2M region*/
#define VEHVA_64M_START         0x040000000000  /*!< Start of 64M region*/
#define VEHVA_64M_END           0x07ffffffffff  /*!< End of 64M region*/
#define VEHVA_256M_START        0x100000000000  /*!< Start of 256M region*/
#define VEHVA_256M_END          0x1fffffffffff  /*!< End of 256M region*/

#endif
