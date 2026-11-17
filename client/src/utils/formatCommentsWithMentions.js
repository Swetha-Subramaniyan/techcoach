import React from "react";

export const renderCommentWithMentions = (commentText = "", members) => {
  const mentionRegex = /@([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g;

  const parts = commentText.split(mentionRegex);

  return parts.map((part, index) => { 
    if (index % 2 === 1) {
      const member = members.find(
        (m) => m.email?.toLowerCase() === part.toLowerCase(),
      );

      if (member) {
        return (
          <span key={index} className="comment__mention">
            @{member.displayname}
          </span>
        );
      }

      return <span key={index}>@{part}</span>;
    }

    return <React.Fragment key={index}>{part}</React.Fragment>;
  });
};
