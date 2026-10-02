// Goodix Tls driver for libfprint

// Copyright (C) 2026 CHAGER5000

// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.

// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.

// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

// Reference implementation: goodix-fp-dump driver_52xd.py
// (https://github.com/CHAGER5000/goodix-fp-dump, branch 521d-capture-fixes)

#define FP_COMPONENT "goodixtls52xd"

#include <glib.h>
#include <string.h>

#include "drivers_api.h"
#include "goodix.h"
#include "goodix_proto.h"
#include "goodix5xx.h"
#include "goodix52xd.h"

#define GOODIX52XD_WIDTH 64
#define GOODIX52XD_HEIGHT 80
#define GOODIX52XD_FRAME_SIZE (GOODIX52XD_WIDTH * GOODIX52XD_HEIGHT)
// The 64x80 image is upscaled like elanspi does: NBIS can't find minutiae in
// it, and SIGFM separates matches from non-matches better at 2x
#define GOODIX52XD_SCALE 2
// For every 4 pixels there are 6 bytes, followed by 4 extra end bytes
#define GOODIX52XD_RAW_FRAME_SIZE (GOODIX52XD_FRAME_SIZE / 4 * 6 + 4)

// The fdt-down event doesn't fire on the 52xd, so the finger is detected by
// polling the 8 fdt region values: a finger lowers each of them by ~45 or
// more, the noise is ~1
#define GOODIX52XD_FDT_REGIONS 8
#define GOODIX52XD_FINGER_DELTA 20
#define GOODIX52XD_FINGER_REGIONS 4
#define GOODIX52XD_POLL_INTERVAL 200

#define GOODIX52XD_CAPTURE_REGISTER 0x022c
#define GOODIX52XD_CAPTURE_ON 0x030a
#define GOODIX52XD_CAPTURE_OFF 0x020a

// fdt-mode with zeroed thresholds and no reply: the report one below isn't
// answered until this was sent (re-sent after each capture to be safe)
static const guint8 fdt_prime_mode[] = {
  0x0d, 0x01, 0x27, 0x01, 0x21, 0x01, 0x27, 0x01, 0x23, 0x01,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// fdt-mode with zeroed thresholds, the reply holds the fdt region values
static const guint8 fdt_report_mode[] = {
  0x0d, 0x01, 0x27, 0x01, 0x21, 0x01, 0x27, 0x01, 0x23, 0x01,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
};

// The 0x45/0xa7 parameters from the Windows trace saturate the sensor, the
// clear frame ones are used for every capture
static const guint8 image_payload[] = {
  0x81, 0x03, 0x27, 0x01, 0x21, 0x01, 0x27, 0x01, 0x23, 0x01,
};

struct _FpiDeviceGoodixTls52xd
{
  FpiDeviceGoodixTls5xx parent;

  GoodixTls5xxPix      *background;
  guint16               fdt_base[GOODIX52XD_FDT_REGIONS];
  FpiSsm               *scan_ssm;
  GSource              *poll_timeout;
};

G_DECLARE_FINAL_TYPE (FpiDeviceGoodixTls52xd, fpi_device_goodixtls52xd, FPI,
                      DEVICE_GOODIXTLS52XD, FpiDeviceGoodixTls5xx);

G_DEFINE_TYPE (FpiDeviceGoodixTls52xd, fpi_device_goodixtls52xd,
               FPI_TYPE_DEVICE_GOODIXTLS5XX);

// ---- ACTIVE SECTION START ----

enum activate_states {
  ACTIVATE_READ_AND_NOP,
  ACTIVATE_CHECK_FW_VER,
  ACTIVATE_CHECK_PSK,
  ACTIVATE_RESET,
  ACTIVATE_READ_CHIP_ID,
  ACTIVATE_READ_OTP,
  ACTIVATE_NUM_STATES,
};

enum activate_tls_states {
  ACTIVATE_TLS_WAIT_ESTABLISHED,
  ACTIVATE_TLS_UPLOAD_MCU_CONFIG,
  ACTIVATE_TLS_NUM_STATES,
};

static void
read_chip_id_callback (FpDevice *dev, guint8 *data, guint16 len,
                       gpointer ssm, GError *err)
{
  if (err)
    {
      fpi_ssm_mark_failed (ssm, err);
      return;
    }

  if (len >= 4)
    fp_dbg ("Chip ID: %02x%02x%02x%02x", data[0], data[1], data[2], data[3]);

  fpi_ssm_next_state (ssm);
}

static void
read_otp_callback (FpDevice *dev, guint8 *data, guint16 len,
                   gpointer ssm, GError *err)
{
  if (err)
    {
      fpi_ssm_mark_failed (ssm, err);
      return;
    }

  // The 52xd firmware replies with an empty OTP, which isn't used anyway
  if (len < 64)
    fp_warn ("Invalid OTP (len: %d), ignoring it", len);

  fpi_ssm_next_state (ssm);
}

static void
activate_run_state (FpiSsm *ssm, FpDevice *dev)
{
  switch (fpi_ssm_get_cur_state (ssm))
    {
    case ACTIVATE_READ_AND_NOP:
      goodix_start_read_loop (dev);
      goodix_send_nop (dev, goodixtls5xx_check_none, ssm);
      break;

    case ACTIVATE_CHECK_FW_VER:
      goodix_send_query_firmware_version (dev, goodixtls5xx_check_firmware_version, ssm);
      break;

    case ACTIVATE_CHECK_PSK:
      goodix_send_preset_psk_read_offset (dev, GOODIX_52XD_PSK_FLAGS,
                                          sizeof (goodix_52xd_psk_0), 0,
                                          goodixtls5xx_check_preset_psk_read,
                                          ssm);
      break;

    case ACTIVATE_RESET:
      goodix_send_reset (dev, TRUE, 20, goodixtls5xx_check_reset, ssm);
      break;

    case ACTIVATE_READ_CHIP_ID:
      goodix_send_read_sensor_register (dev, 0x0000, 4, read_chip_id_callback,
                                        ssm);
      break;

    case ACTIVATE_READ_OTP:
      goodix_send_read_otp (dev, read_otp_callback, ssm);
      break;
    }
}

static void
activate_tls_run_state (FpiSsm *ssm, FpDevice *dev)
{
  switch (fpi_ssm_get_cur_state (ssm))
    {
    case ACTIVATE_TLS_WAIT_ESTABLISHED:
      // goodix_tls_init() doesn't wait for the tls_successfully_established
      // ack, which the 52xd sends ~20ms later: a command sent before that
      // isn't answered
      fpi_ssm_next_state_delayed (ssm, 50);
      break;

    case ACTIVATE_TLS_UPLOAD_MCU_CONFIG:
      goodix_send_upload_config_mcu (dev, goodix_52xd_config,
                                     sizeof (goodix_52xd_config), NULL,
                                     goodixtls5xx_check_config_upload, ssm);
      break;
    }
}

static void
activate_tls_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  if (error)
    fp_err ("failed during activation: %s (code: %d)", error->message,
            error->code);

  fpi_image_device_activate_complete (FP_IMAGE_DEVICE (dev), error);
}

static void
tls_activation_complete (FpDevice *dev, gpointer user_data, GError *error)
{
  if (error)
    {
      fp_err ("failed to complete tls activation: %s", error->message);
      fpi_image_device_activate_complete (FP_IMAGE_DEVICE (dev), error);
      return;
    }

  // Unlike the 511, the config is uploaded once the TLS connection is up
  fpi_ssm_start (fpi_ssm_new (dev, activate_tls_run_state,
                              ACTIVATE_TLS_NUM_STATES),
                 activate_tls_complete);
}

static void
activate_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  G_DEBUG_HERE ();
  if (!error)
    {
      goodix_tls_init (dev, tls_activation_complete, NULL);
    }
  else
    {
      fp_err ("failed during activation: %s (code: %d)", error->message,
              error->code);
      fpi_image_device_activate_complete (FP_IMAGE_DEVICE (dev), error);
    }
}

// ---- ACTIVE SECTION END ----

// -----------------------------------------------------------------------------

// ---- SCAN SECTION START ----

enum scan_states {
  SCAN_FDT_PRIME,
  SCAN_BACKGROUND_ON,
  SCAN_BACKGROUND_GET_IMG,
  SCAN_BACKGROUND_OFF,
  SCAN_FDT_BASE_PRIME,
  SCAN_FDT_BASE,
  SCAN_WAIT_FINGER_DOWN,
  SCAN_CAPTURE_ON,
  SCAN_GET_IMG,
  SCAN_CAPTURE_OFF,
  SCAN_FDT_UP_PRIME,
  SCAN_WAIT_FINGER_UP,
  SCAN_NUM_STATES,
};

static gboolean
read_fdt_values (guint8 *data, guint16 len, guint16 *values, GError **error)
{
  // 4 status bytes followed by the region values
  if (len < 4 + GOODIX52XD_FDT_REGIONS * 2)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                   "Invalid fdt reply length: %d", len);
      return FALSE;
    }

  for (int i = 0; i != GOODIX52XD_FDT_REGIONS; ++i)
    values[i] = data[4 + i * 2] | data[5 + i * 2] << 8;

  return TRUE;
}

static gboolean
finger_present (FpiDeviceGoodixTls52xd *self, const guint16 *values)
{
  int regions = 0;

  for (int i = 0; i != GOODIX52XD_FDT_REGIONS; ++i)
    if (self->fdt_base[i] - values[i] > GOODIX52XD_FINGER_DELTA)
      regions++;

  return regions >= GOODIX52XD_FINGER_REGIONS;
}

static void
decode_frame (GoodixTls5xxPix *frame, guint8 *data)
{
  GoodixTls5xxPix *pix = frame;

  for (int i = 0; i != GOODIX52XD_RAW_FRAME_SIZE - 4; i += 6)
    {
      const guint8 *chunk = data + i;
      *pix++ = ((chunk[0] & 0xf) << 8) + chunk[1];
      *pix++ = (chunk[3] << 4) + (chunk[0] >> 4);
      *pix++ = ((chunk[5] & 0xf) << 8) + chunk[2];
      *pix++ = (chunk[4] << 4) + (chunk[5] >> 4);
    }
}

static int
compare_int (const void *a, const void *b)
{
  return *(const int *) a - *(const int *) b;
}

static FpImage *
subtract_background (FpiDeviceGoodixTls52xd *self, const GoodixTls5xxPix *frame)
{
  // The ridges are much weaker than the sensor fixed pattern, so the image
  // is the frame minus the background, stretched between the 1st and 99th
  // percentiles of the live pixels (the border is dead and reads 0, and the
  // pixels next to it would flatten a min/max stretch)
  FpImage *img = fp_image_new (GOODIX52XD_WIDTH, GOODIX52XD_HEIGHT);
  g_autofree int *sorted = g_new (int, GOODIX52XD_FRAME_SIZE);
  int live = 0;
  int lo, hi;

  for (int i = 0; i != GOODIX52XD_FRAME_SIZE; ++i)
    if (self->background[i])
      sorted[live++] = frame[i] - self->background[i];

  if (live)
    {
      qsort (sorted, live, sizeof (int), compare_int);
      lo = sorted[live / 100];
      hi = sorted[live - 1 - live / 100];
    }
  else
    {
      lo = hi = 0;
    }

  for (int i = 0; i != GOODIX52XD_FRAME_SIZE; ++i)
    {
      const int diff = frame[i] - self->background[i];

      if (!self->background[i] || hi <= lo)
        img->data[i] = 0xff;
      else
        img->data[i] = CLAMP ((diff - lo) * 0xff / (hi - lo), 0, 0xff);
    }

  img->flags |= FPI_IMAGE_PARTIAL;

  FpImage *scaled = fpi_image_resize (img, GOODIX52XD_SCALE, GOODIX52XD_SCALE);

  g_object_unref (img);
  return scaled;
}

static void
poll_finger_down (FpDevice *dev, gpointer ssm)
{
  FpiDeviceGoodixTls52xd *self = FPI_DEVICE_GOODIXTLS52XD (dev);

  self->poll_timeout = NULL;
  fpi_ssm_jump_to_state (ssm, SCAN_WAIT_FINGER_DOWN);
}

static void
poll_finger_up (FpDevice *dev, gpointer ssm)
{
  FpiDeviceGoodixTls52xd *self = FPI_DEVICE_GOODIXTLS52XD (dev);

  self->poll_timeout = NULL;
  fpi_ssm_jump_to_state (ssm, SCAN_WAIT_FINGER_UP);
}

static void
send_fdt_prime (FpDevice *dev, FpiSsm *ssm)
{
  // goodix_send_mcu_switch_to_fdt_mode() always waits for a reply
  GoodixCallbackInfo *cb_info = malloc (sizeof (GoodixCallbackInfo));

  cb_info->callback = G_CALLBACK (goodixtls5xx_check_none);
  cb_info->user_data = ssm;

  goodix_send_protocol (dev, GOODIX_CMD_MCU_SWITCH_TO_FDT_MODE, fdt_prime_mode,
                        sizeof (fdt_prime_mode), NULL, TRUE, GOODIX_TIMEOUT,
                        FALSE, goodix_receive_none, cb_info);
}

static void
scan_on_background (FpDevice *dev, guint8 *data, guint16 len, gpointer ssm,
                    GError *err)
{
  FpiDeviceGoodixTls52xd *self = FPI_DEVICE_GOODIXTLS52XD (dev);

  if (err)
    {
      fpi_ssm_mark_failed (ssm, err);
      return;
    }

  if (len < GOODIX52XD_RAW_FRAME_SIZE)
    {
      fpi_ssm_mark_failed (ssm, g_error_new (FP_DEVICE_ERROR,
                                             FP_DEVICE_ERROR_DATA_INVALID,
                                             "Invalid frame length: %d", len));
      return;
    }

  if (!self->background)
    self->background = g_new0 (GoodixTls5xxPix, GOODIX52XD_FRAME_SIZE);
  decode_frame (self->background, data);

  fpi_ssm_next_state (ssm);
}

static void
scan_on_fdt_base (FpDevice *dev, guint8 *data, guint16 len, gpointer ssm,
                  GError *err)
{
  FpiDeviceGoodixTls52xd *self = FPI_DEVICE_GOODIXTLS52XD (dev);

  if (err)
    {
      fpi_ssm_mark_failed (ssm, err);
      return;
    }

  if (!read_fdt_values (data, len, self->fdt_base, &err))
    {
      fpi_ssm_mark_failed (ssm, err);
      return;
    }

  fp_dbg ("fdt base: %03x %03x %03x %03x %03x %03x %03x %03x",
          self->fdt_base[0], self->fdt_base[1], self->fdt_base[2],
          self->fdt_base[3], self->fdt_base[4], self->fdt_base[5],
          self->fdt_base[6], self->fdt_base[7]);

  fpi_ssm_next_state (ssm);
}

static void
scan_on_fdt_down (FpDevice *dev, guint8 *data, guint16 len, gpointer ssm,
                  GError *err)
{
  FpiDeviceGoodixTls52xd *self = FPI_DEVICE_GOODIXTLS52XD (dev);
  guint16 values[GOODIX52XD_FDT_REGIONS];

  if (err)
    {
      fpi_ssm_mark_failed (ssm, err);
      return;
    }

  if (!read_fdt_values (data, len, values, &err))
    {
      fpi_ssm_mark_failed (ssm, err);
      return;
    }

  if (!finger_present (self, values))
    {
      // Not a delayed ssm transition, so that reset_state can stop it
      self->poll_timeout = fpi_device_add_timeout (dev, GOODIX52XD_POLL_INTERVAL,
                                                   poll_finger_down, ssm, NULL);
      return;
    }

  fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (dev), TRUE);
  fpi_ssm_next_state (ssm);
}

static void
scan_on_read_img (FpDevice *dev, guint8 *data, guint16 len, gpointer ssm,
                  GError *err)
{
  FpiDeviceGoodixTls52xd *self = FPI_DEVICE_GOODIXTLS52XD (dev);

  if (err)
    {
      fpi_ssm_mark_failed (ssm, err);
      return;
    }

  if (len < GOODIX52XD_RAW_FRAME_SIZE)
    {
      fpi_ssm_mark_failed (ssm, g_error_new (FP_DEVICE_ERROR,
                                             FP_DEVICE_ERROR_DATA_INVALID,
                                             "Invalid frame length: %d", len));
      return;
    }

  g_autofree GoodixTls5xxPix *frame = g_new0 (GoodixTls5xxPix,
                                              GOODIX52XD_FRAME_SIZE);
  decode_frame (frame, data);

  fpi_image_device_image_captured (FP_IMAGE_DEVICE (dev),
                                   subtract_background (self, frame));

  fpi_ssm_next_state (ssm);
}

static void
scan_on_fdt_up (FpDevice *dev, guint8 *data, guint16 len, gpointer ssm,
                GError *err)
{
  FpiDeviceGoodixTls52xd *self = FPI_DEVICE_GOODIXTLS52XD (dev);
  guint16 values[GOODIX52XD_FDT_REGIONS];

  if (err)
    {
      fpi_ssm_mark_failed (ssm, err);
      return;
    }

  if (!read_fdt_values (data, len, values, &err))
    {
      fpi_ssm_mark_failed (ssm, err);
      return;
    }

  if (finger_present (self, values))
    {
      self->poll_timeout = fpi_device_add_timeout (dev, GOODIX52XD_POLL_INTERVAL,
                                                   poll_finger_up, ssm, NULL);
      return;
    }

  // Complete the scan first: reporting the finger off can deactivate the
  // device, and reset_state() then frees a still running scan_ssm
  fpi_ssm_next_state (ssm);
  fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (dev), FALSE);
}

static void
scan_run_state (FpiSsm *ssm, FpDevice *dev)
{
  switch (fpi_ssm_get_cur_state (ssm))
    {
    case SCAN_FDT_PRIME:
    case SCAN_FDT_BASE_PRIME:
    case SCAN_FDT_UP_PRIME:
      send_fdt_prime (dev, ssm);
      break;

    case SCAN_BACKGROUND_ON:
    case SCAN_CAPTURE_ON:
      goodix_send_write_sensor_register (dev, GOODIX52XD_CAPTURE_REGISTER,
                                         GOODIX52XD_CAPTURE_ON,
                                         goodixtls5xx_check_none, ssm);
      break;

    case SCAN_BACKGROUND_GET_IMG:
      goodix_tls_read_image_payload (dev, image_payload, sizeof (image_payload),
                                     scan_on_background, ssm);
      break;

    case SCAN_BACKGROUND_OFF:
    case SCAN_CAPTURE_OFF:
      goodix_send_write_sensor_register (dev, GOODIX52XD_CAPTURE_REGISTER,
                                         GOODIX52XD_CAPTURE_OFF,
                                         goodixtls5xx_check_none, ssm);
      break;

    case SCAN_FDT_BASE:
      goodix_send_mcu_switch_to_fdt_mode (dev, fdt_report_mode,
                                          sizeof (fdt_report_mode), NULL,
                                          scan_on_fdt_base, ssm);
      break;

    case SCAN_WAIT_FINGER_DOWN:
      goodix_send_mcu_switch_to_fdt_mode (dev, fdt_report_mode,
                                          sizeof (fdt_report_mode), NULL,
                                          scan_on_fdt_down, ssm);
      break;

    case SCAN_GET_IMG:
      goodix_tls_read_image_payload (dev, image_payload, sizeof (image_payload),
                                     scan_on_read_img, ssm);
      break;

    case SCAN_WAIT_FINGER_UP:
      goodix_send_mcu_switch_to_fdt_mode (dev, fdt_report_mode,
                                          sizeof (fdt_report_mode), NULL,
                                          scan_on_fdt_up, ssm);
      break;
    }
}

static void
scan_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodixTls52xd *self = FPI_DEVICE_GOODIXTLS52XD (dev);

  self->scan_ssm = NULL;

  if (error)
    {
      fp_err ("failed to scan: %s (code: %d)", error->message, error->code);
      fpi_image_device_session_error (FP_IMAGE_DEVICE (dev), error);
      return;
    }
  fp_dbg ("finished scan");
}

static void
scan_start (FpDevice *dev)
{
  FpiDeviceGoodixTls52xd *self = FPI_DEVICE_GOODIXTLS52XD (dev);

  self->scan_ssm = fpi_ssm_new (dev, scan_run_state, SCAN_NUM_STATES);
  fpi_ssm_start (self->scan_ssm, scan_complete);
}

// ---- SCAN SECTION END ----

// ---- DEV SECTION START ----

static void
dev_activate (FpImageDevice *img_dev)
{
  FpDevice *dev = FP_DEVICE (img_dev);

  fpi_ssm_start (fpi_ssm_new (dev, activate_run_state, ACTIVATE_NUM_STATES),
                 activate_complete);
}

static void
reset_state (FpDevice *dev)
{
  FpiDeviceGoodixTls52xd *self = FPI_DEVICE_GOODIXTLS52XD (dev);

  // Called on deactivation, after goodix_reset_state() dropped the pending
  // command callback: stop a scan that is still waiting for the finger
  g_clear_pointer (&self->poll_timeout, g_source_destroy);
  g_clear_pointer (&self->scan_ssm, fpi_ssm_free);
  g_clear_pointer (&self->background, g_free);
}

// ---- DEV SECTION END ----

static void
fpi_device_goodixtls52xd_init (FpiDeviceGoodixTls52xd *self)
{
}

static void
fpi_device_goodixtls52xd_finalize (GObject *object)
{
  FpiDeviceGoodixTls52xd *self = FPI_DEVICE_GOODIXTLS52XD (object);

  g_clear_pointer (&self->background, g_free);

  G_OBJECT_CLASS (fpi_device_goodixtls52xd_parent_class)->finalize (object);
}

static void
fpi_device_goodixtls52xd_class_init (FpiDeviceGoodixTls52xdClass *class)
{
  GObjectClass *object_class = G_OBJECT_CLASS (class);
  FpiDeviceGoodixTlsClass *gx_class = FPI_DEVICE_GOODIXTLS_CLASS (class);
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (class);
  FpImageDeviceClass *img_dev_class = FP_IMAGE_DEVICE_CLASS (class);
  FpiDeviceGoodixTls5xxClass *xx_cls = FPI_DEVICE_GOODIXTLS5XX_CLASS (class);

  object_class->finalize = fpi_device_goodixtls52xd_finalize;

  xx_cls->scan_start = scan_start;
  xx_cls->reset_state = reset_state;
  xx_cls->scan_height = GOODIX52XD_HEIGHT;
  xx_cls->scan_width = GOODIX52XD_WIDTH;
  xx_cls->psk = goodix_52xd_psk_0;
  xx_cls->psk_flags = GOODIX_52XD_PSK_FLAGS;
  xx_cls->psk_len = sizeof (goodix_52xd_psk_0);
  xx_cls->firmware_version = GOODIX_52XD_FIRMWARE_VERSION;
  xx_cls->reset_number = GOODIX_52XD_RESET_NUMBER;

  gx_class->interface = GOODIX_52XD_INTERFACE;
  gx_class->ep_in = GOODIX_52XD_EP_IN;
  gx_class->ep_out = GOODIX_52XD_EP_OUT;

  dev_class->id = "goodixtls52xd";
  dev_class->full_name = "Goodix TLS Fingerprint Sensor 52xd";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->nr_enroll_stages = 20;

  dev_class->scan_type = FP_SCAN_TYPE_PRESS;

  // NBIS minutiae are unreliable on such a small image (64x80, upscaled to
  // 128x160), SIGFM is used instead and bz3_threshold is its score threshold.
  // Offline, at 2x, overlapping captures of the same finger score 64-97 and
  // non-overlapping ones 0-4
  img_dev_class->algorithm = FPI_DEVICE_ALGO_SIGFM;
  img_dev_class->bz3_threshold = 24;
  img_dev_class->img_width = GOODIX52XD_WIDTH * GOODIX52XD_SCALE;
  img_dev_class->img_height = GOODIX52XD_HEIGHT * GOODIX52XD_SCALE;

  img_dev_class->activate = dev_activate;

  fpi_device_class_auto_initialize_features (dev_class);
}
