package com.boomaa.opends.display;

import org.jnativehook.keyboard.NativeKeyEvent;
import org.jnativehook.keyboard.NativeKeyListener;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class GlobalKeyListener implements NativeKeyListener {
    public static final GlobalKeyListener INSTANCE = new GlobalKeyListener();
    private static final Map<Integer, Runnable> keyMap = new HashMap<>();
    private static final List<MultiKeyEvent> multiKeyList = new ArrayList<>();

    private GlobalKeyListener() {
    }

    public GlobalKeyListener addKeyEvent(int keyCode, Runnable action) {
        keyMap.put(keyCode, action);
        return this;
    }

    public GlobalKeyListener addMultiKeyEvent(MultiKeyEvent event) {
        multiKeyList.add(event);
        return this;
    }

    @Override
    public void nativeKeyPressed(NativeKeyEvent nativeKeyEvent) {
        updateMultiKey(nativeKeyEvent, true);
        doAction(nativeKeyEvent);
    }

    @Override
    public void nativeKeyReleased(NativeKeyEvent nativeKeyEvent) {
        updateMultiKey(nativeKeyEvent, false);
    }

    @Override
    public void nativeKeyTyped(NativeKeyEvent nativeKeyEvent) {
    }

    public void doAction(NativeKeyEvent event) {
        int keycode = event.getKeyCode();
        if (keyMap.containsKey(keycode)) {
            keyMap.get(keycode).run();
        }
        for (MultiKeyEvent mkEvent : multiKeyList) {
            mkEvent.pollAction();
        }
    }

    public void updateMultiKey(NativeKeyEvent event, boolean pressed) {
        for (MultiKeyEvent mkEvent : multiKeyList) {
            mkEvent.update(event.getKeyCode(), pressed);
        }
    }
}
