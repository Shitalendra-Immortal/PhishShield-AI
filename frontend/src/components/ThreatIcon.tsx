import type { SVGProps } from "react";

export function ThreatIcon({
  className = "h-5 w-5",
  ...props
}: SVGProps<SVGSVGElement>) {
  return (
    <svg
      viewBox="0 0 48 48"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      aria-hidden="true"
      {...props}
    >
      <defs>
        <linearGradient
          id="threatIconFlameGrad"
          x1="7"
          y1="7"
          x2="41"
          y2="41"
          gradientUnits="userSpaceOnUse"
        >
          <stop offset="0%" stopColor="#F15B3B" />
          <stop offset="100%" stopColor="#FF874C" />
        </linearGradient>
      </defs>

      {/* Hat Dome */}
      <path
        d="M11.5 18C11.5 10.5 16.5 7 24 7C31.5 7 36.5 10.5 36.5 18H11.5Z"
        fill="url(#threatIconFlameGrad)"
      />

      {/* Hat Brim */}
      <rect
        x="7"
        y="17"
        width="34"
        height="7"
        rx="3.5"
        fill="url(#threatIconFlameGrad)"
      />

      {/* Bandit / Threat Mask with Eye Cutouts */}
      <path
        fillRule="evenodd"
        clipRule="evenodd"
        d="M10 26.5H38C39.4 26.5 40.5 27.6 40.5 29V32C40.5 37 37 41 32.5 41C28.2 41 25.8 38.6 24 36.8C22.2 38.6 19.8 41 15.5 41C11 41 7.5 37 7.5 32V29C7.5 27.6 8.6 26.5 10 26.5ZM13 30.25C12.03 30.25 11.25 31.03 11.25 32C11.25 32.97 12.03 33.75 13 33.75H19C19.97 33.75 20.75 32.97 20.75 32C20.75 31.03 19.97 30.25 19 30.25H13ZM29 30.25C28.03 30.25 27.25 31.03 27.25 32C27.25 32.97 28.03 33.75 29 33.75H35C35.97 33.75 36.75 32.97 36.75 32C36.75 31.03 35.97 30.25 35 30.25H29Z"
        fill="url(#threatIconFlameGrad)"
      />
    </svg>
  );
}

