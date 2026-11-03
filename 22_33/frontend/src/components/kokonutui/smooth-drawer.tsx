"use client";

/**
 * @author: @dorianbaffier
 * @description: Smooth Drawer
 * @version: 2.0.0
 * @date: 2026-10-16
 * @license: MIT
 * @website: https://kokonutui.com
 * @github: https://github.com/kokonut-labs/kokonutui
 */

// Adapted from Kokonut's Smooth Drawer for message evidence instead of an order summary.
// Keeps Vaul snap points and staggered Motion content reveal.
import { useState, type ReactNode } from "react";
import { motion, useReducedMotion } from "motion/react";
import { Button } from "@/components/ui/button";
import {
  Drawer,
  DrawerContent,
  DrawerDescription,
  DrawerTitle,
  DrawerTrigger,
  DrawerClose,
} from "@/components/ui/drawer";

export default function SmoothDrawer({
  title,
  description,
  triggerLabel,
  children,
}: {
  title: string;
  description: string;
  triggerLabel: string;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const [snap, setSnap] = useState<string | number | null>(1);
  const reduced = useReducedMotion();
  return (
    <Drawer
      open={open}
      onOpenChange={(value) => {
        setOpen(value);
        if (value) setSnap(1);
      }}
      snapPoints={[0.45, 1]}
      activeSnapPoint={snap}
      setActiveSnapPoint={setSnap}
    >
      <DrawerTrigger asChild>
        <Button variant="outline" size="sm">
          {triggerLabel}
        </Button>
      </DrawerTrigger>
      <DrawerContent className="signature-drawer">
        <div className="drawer-heading">
          <div>
            <DrawerTitle>{title}</DrawerTitle>
            <DrawerDescription>{description}</DrawerDescription>
          </div>
          <DrawerClose asChild>
            <Button variant="ghost" size="sm">
              Close
            </Button>
          </DrawerClose>
        </div>
        <div className="drawer-evidence" data-vaul-no-drag>
          <motion.div
            initial={{ opacity: 0, y: reduced ? 0 : 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{
              duration: reduced ? 0 : 0.3,
              delay: reduced ? 0 : 0.08,
            }}
          >
            {children}
          </motion.div>
        </div>
      </DrawerContent>
    </Drawer>
  );
}
