package org.openrepose.core.services.event.common.impl;

import org.openrepose.core.services.event.common.EventListener;

import java.util.*;

public class EventListenerDescriptor<T extends Enum> {

    private final EventListener<T, ?> listener;
    private final Set<T> subscriptions;

    public EventListenerDescriptor(EventListener<T, ?> listener, Collection<T> targetedEvents) {
        this.subscriptions = new HashSet<T>(targetedEvents);
        this.listener = listener;
    }

    public EventListener<T, ?> getListener() {
        return listener;
    }

    public void listenFor(Collection<T> types) {
        subscriptions.addAll(types);
    }

    public boolean silence(Collection<T> types) {
        // Create a local copy
        final List<T> typesToRemove = new LinkedList<T>(types);
        final Iterator<T> targetedEventIterator = subscriptions.iterator();

        while (targetedEventIterator.hasNext()) {
            final T event = targetedEventIterator.next();
            
            if (typesToRemove.remove(event)) {
                targetedEventIterator.remove();
            }
        }

        return subscriptions.isEmpty();
    }

    public boolean answersTo(T typeToLookFor) {
        for (T eventType : subscriptions) {
            if (eventType == typeToLookFor) {
                return true;
            }
        }

        return false;
    }
}
