#ifndef VEOS_VE1_AMM_VEHVA_MGMT_VE1_H
#define VEOS_VE1_AMM_VEHVA_MGMT_VE1_H
#include <libved.h>
#include <ve_hw.h>
#define VESHM_END_ENTRY (VE1_DMAATB_ENTRY_MAX_SIZE * VE1_DMAATB_DIR_NUM)

#define VEHVA_4K_START		0x000000000000	/*!< Start of 4K region*/
#define VEHVA_4K_END		0x000003ffffff	/*!< End of 4K region*/
#define VEHVA_2M_START		0x008800000000	/*!< Start of 2M region*/
#define VEHVA_2M_END		0x008fffffffff	/*!< End of 2M region*/
#define VEHVA_64M_START		0x070000000000	/*!< Start of 64M region*/
#define VEHVA_64M_END		0x07ffffffffff	/*!< End of 64M region*/

#endif
