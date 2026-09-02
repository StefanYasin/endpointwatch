try:
    import simpleaudio as sa
except ImportError:
    sa = None  # audio is optional; the package works silently without it

import os

class AudioAlerts:
    def __init__(self, sound_dir="sounds"):
        self.sound_dir = sound_dir
        self.sounds = {
            "info": "info.wav",
            "warn": "warn.wav",
            "alert": "alert.wav"
        }

    def play(self, level="info"):
        if sa is None:
            return
        try:
            file = self.sounds.get(level)
            if not file: return
            path = os.path.join(self.sound_dir, file)
            if os.path.exists(path):
                sa.WaveObject.from_wave_file(path).play()
        except Exception as e:
            print(f"[AudioError] {e}")